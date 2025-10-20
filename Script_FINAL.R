################################################################################
#  ENTROPY- & PARAMETER-AWARE PIPELINE FOR RANSOMWARE DETECTION
#  ============================================================================
#  • Seven heterogeneous models: Random Forest, SVM-RBF, Elastic-Net,
#    XGBoost, MGM, Bayesian Network, H2O Deep Autoencoder.
#  • 40 outer folds with 70 / 30 stratified split; outer 30 % is pure hold-out.
#  • Autoencoder hyperparameters selected via manual 5-fold CV inside the 70 %.
#  • Single H2O cluster is started once at the top and shut down at the end.
################################################################################

############################ 0. GLOBAL CONSTANTS & LIBRARIES ##################
outer_folds <- 40L       # number of outer CV folds
set.seed(1)              # reproducibility seed
num_bins   <- 7L         # bins for BN discretisation
eps_small  <- 1e-12      # guard for zero entropy/parameters


if (!requireNamespace("curl", quietly = TRUE)) {
  install.packages("curl", dependencies = TRUE)
}
options(prefer_RCurl = FALSE)
library(curl)
library(h2o)

h2o.init(
  ip        = "127.0.0.1",
  port      = 54321,
  nthreads  = -1,
  startH2O  = TRUE
)
h2o.no_progress()

# required packages
pkgs <- c(
  "readxl","caret","ranger","kernlab","glmnet","xgboost","mgm",
  "TSEntropies","bnlearn","iml","ggplot2","knitr","tidygraph",
  "ggraph","igraph","patchwork","RColorBrewer","FactoMineR","factoextra","h2o"
)
need <- pkgs[!pkgs %in% rownames(installed.packages())]
if (length(need)) install.packages(need, dependencies = TRUE)
invisible(lapply(pkgs, require, character.only = TRUE))

# initialise H2O once
h2o.init(nthreads = -1)
h2o.no_progress()

########################### 1. UTILITY FUNCTIONS ##############################
reshape_sheet <- function(df, c_win = 9L, slots = 10L) {
  # reshape flat data frame into [samples × counters × windows] array
  s <- nrow(df); w <- as.integer(ncol(df) / c_win)
  a <- array(NA_real_, c(s, slots, w))
  for (k in seq_len(w)) {
    idx <- ((k - 1L) * c_win + 1L):(k * c_win)
    a[, 1:c_win, k] <- as.matrix(df[, idx])
  }
  a
}

entropy_vec <- function(v) SampEn(v)  # sample entropy

append_entropy <- function(arr, y, win = 50L) {
  # compute entropies for first `win` windows, add label
  idx <- 1:win
  data.frame(
    L1.dcache.loads       = apply(arr[,2,idx], 1, entropy_vec),
    dTLB_load             = apply(arr[,3,idx], 1, entropy_vec),
    L1.dcache.stores      = apply(arr[,4,idx], 1, entropy_vec),
    branch.loads          = apply(arr[,5,idx], 1, entropy_vec),
    L1.dcache.load.misses = apply(arr[,6,idx], 1, entropy_vec),
    mem.stores            = apply(arr[,7,idx], 1, entropy_vec),
    iTLB.loads            = apply(arr[,8,idx], 1, entropy_vec),
    branches              = apply(arr[,9,idx], 1, entropy_vec),
    Ransomware            = factor(y, levels = c(FALSE, TRUE))
  )
}

safe_scale <- function(df) {
  # z-score numeric columns, drop incomplete rows
  num <- sapply(df, is.numeric)
  for (j in which(num)) {
    x <- df[[j]]; x[is.infinite(x)] <- NA
    df[[j]] <- as.numeric(scale(x))
  }
  df[complete.cases(df), ]
}

compute_metrics <- function(pred, truth) {
  # binary Accuracy, F1, Matthews φ
  lv <- levels(truth)
  pred <- factor(pred, lv); truth <- factor(truth, lv)
  cm <- table(truth, pred)
  tp <- cm[2,2]; tn <- cm[1,1]; fp <- cm[1,2]; fn <- cm[2,1]
  acc <- (tp + tn) / sum(cm)
  f1  <- if ((2*tp + fp + fn) == 0) NA else 2*tp / (2*tp + fp + fn)
  den <- sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
  phi <- if (den == 0) NA else (tp*tn - fp*fn) / den
  c(Accuracy = acc, F1 = f1, Phi = phi)
}

sh_entropy <- function(v) {
  # Shannon entropy of vector v (zero if all zero)
  if (length(v) == 0) return(NA_real_)
  if (sum(v) == 0)    return(0)
  p <- v / sum(v); p <- p[p > 0]; -sum(p * log2(p))
}

get_bn_strengths <- function(bn, data, target = "Ransomware") {
  # mutual-information strengths of arcs to/from target
  if (inherits(bn, "bn.fit"))
    bn <- bnlearn::model2network(bnlearn::modelstring(bn))
  st <- bnlearn::arc.strength(bn, data = data, criterion = "mi")
  preds <- setdiff(names(data), target)
  v <- setNames(numeric(length(preds)), preds)
  sel <- st$from == target | st$to == target
  if (any(sel)) for (i in which(sel)) {
    a <- st[i,]; p <- ifelse(a$from == target, a$to, a$from)
    v[p] <- max(v[p], a$strength)
  }
  v
}

# parameter counters for each model
param_count_rf   <- function(fit) sum(sapply(fit$finalModel$forest$split.varIDs, length))
param_count_svm  <- function(fit) sum(fit$finalModel@nSV) + 2
param_count_enet <- function(fit) sum(abs(as.vector(coef(fit$finalModel, s = fit$bestTune$lambda))) > 0)
param_count_xgb  <- function(fit) nrow(xgboost::xgb.model.dt.tree(model = fit$finalModel))
param_count_mgm  <- function(fit) sum(abs(fit$pairwise$wadj) > 0) / 2
param_count_bn   <- function(fit) bnlearn::nparams(fit)
param_count_ae   <- function(ae)  sum(unlist(ae@model$run_info$parameters))

# efficiency ratios
ratio_entropy <- function(acc, H) ifelse(is.na(H) | H <= eps_small, 0, acc / H)
ratio_params  <- function(acc, p, link) ifelse(!link | p <= eps_small, 0, acc / p)


######################## 1b. SUPERVISED MODEL TRAINERS ########################
train_ranger <- function(tr, te, k = 5) {
  mdl <- caret::train(
    x = tr[, -which(names(tr) == "Ransomware")],
    y = tr$Ransomware,
    method = "ranger",
    trControl = trainControl(method = "repeatedcv", number = k)
  )
  pr <- predict(mdl, te[, -which(names(te) == "Ransomware")])
  list(model = mdl, metrics = compute_metrics(pr, te$Ransomware))
}

train_svm_rbf <- function(tr, te, k = 5) {
  tune <- expand.grid(sigma = c(0.001, 0.01, 0.1, 0.5),
                      C     = c(0.1, 1, 10, 100))
  mdl <- caret::train(
    x = tr[, -which(names(tr) == "Ransomware")],
    y = tr$Ransomware,
    method = "svmRadial",
    tuneGrid = tune,
    trControl = trainControl(method = "repeatedcv", number = k)
  )
  pr <- predict(mdl, te[, -which(names(te) == "Ransomware")])
  list(model = mdl, metrics = compute_metrics(pr, te$Ransomware))
}

train_glmnet <- function(tr, te, k = 5) {
  mdl <- caret::train(
    x = tr[, -which(names(tr) == "Ransomware")],
    y = tr$Ransomware,
    method = "glmnet",
    tuneLength = 10,
    trControl = trainControl(method = "repeatedcv", number = k)
  )
  pr <- predict(mdl, te[, -which(names(te) == "Ransomware")])
  list(model = mdl, metrics = compute_metrics(pr, te$Ransomware))
}

train_xgb <- function(tr, te, k = 5) {
  tune <- expand.grid(nrounds = c(50, 100),
                      max_depth = c(3, 6),
                      eta = c(0.01, 0.1),
                      gamma = 0,
                      colsample_bytree = 1,
                      min_child_weight = 1,
                      subsample = 1)
  mdl <- caret::train(
    x = tr[, -which(names(tr) == "Ransomware")],
    y = tr$Ransomware,
    method = "xgbTree",
    tuneGrid = tune,
    trControl = trainControl(method = "repeatedcv", number = k)
  )
  pr <- predict(mdl, te[, -which(names(te) == "Ransomware")])
  list(model = mdl, metrics = compute_metrics(pr, te$Ransomware))
}

jitter_constant <- function(mat, idx, eps = 1e-5) {
  const <- which(apply(mat[idx, , drop = FALSE], 2, sd) == 0)
  if (length(const))
    mat[, const] <- mat[, const] +
      matrix(rnorm(nrow(mat) * length(const), 0, eps),
             ncol = length(const))
  mat
}


###################### 2. DATA IMPORT & PRE-PROCESSING ########################
ds_b <- readxl::read_excel("Cartel1.xlsx", sheet = "Benign")
ds_r <- readxl::read_excel("Cartel1.xlsx", sheet = "Ransomware")

arr_b <- reshape_sheet(as.data.frame(ds_b))
arr_r <- reshape_sheet(as.data.frame(ds_r))

data_df <- rbind(append_entropy(arr_r, TRUE),
                 append_entropy(arr_b, FALSE)) |> safe_scale()

# discretised copy for Bayesian Net
num_idx <- which(sapply(data_df, is.numeric))
disc_df <- data_df; drop_c <- character(0)
for (j in num_idx) {
  x <- data_df[[j]]
  if (length(unique(x)) < 2) { drop_c <- c(drop_c, names(data_df)[j]); next }
  d <- try(bnlearn::discretize(data.frame(x), method = "quantile",
                               breaks = num_bins, ordered = TRUE)[,1],
           silent = TRUE)
  if (inherits(d,"try-error") || length(levels(d)) < 2)
    d <- bnlearn::discretize(data.frame(x), method = "interval",
                             breaks = num_bins, ordered = TRUE)[,1]
  if (length(levels(d)) < 2) drop_c <- c(drop_c, names(data_df)[j])
  else disc_df[[j]] <- d
}
if (length(drop_c)) disc_df[drop_c] <- NULL


################################ 3. OUTER CV LOOP #############################
hidden_grid <- list(
  `10-8-4-8-10` = c(10,8,4,8,10)
)

# prepare storage
out        <- vector("list", outer_folds)
best_arch  <- character(outer_folds)
H_rf <- H_svm <- H_enet <- H_xgb <- H_mgm <- H_bn <- H_ae <- numeric(outer_folds)
P_rf <- P_svm <- P_enet <- P_xgb <- P_mgm <- P_bn <- P_ae <- numeric(outer_folds)
ratio_rf <- ratio_svm <- ratio_enet <- ratio_xgb <- ratio_mgm <- ratio_bn <- ratio_ae <- numeric(outer_folds)
ratioP_rf<- ratioP_svm<- ratioP_enet<- ratioP_xgb<- ratioP_mgm<- ratioP_bn<- ratioP_ae<- numeric(outer_folds)
ae_imp_all <- list()

for (fold in seq_len(outer_folds)) {
  set.seed(fold)
  cat(sprintf("===== OUTER FOLD %d / %d =====\n", fold, outer_folds))
  
  # split 70/30
  idx_tr <- caret::createDataPartition(data_df$Ransomware, p = .7, list = FALSE)
  tr <- data_df[idx_tr, ]; te <- data_df[-idx_tr, ]
  
  # train supervised models
  rf   <- train_ranger(tr, te)
  svm  <- train_svm_rbf(tr, te)
  enet <- train_glmnet(tr, te)
  xgb  <- train_xgb(tr, te)
  
  # compute feature-importance entropy
  get_imp <- function(mdl)
    iml::FeatureImp$new(
      iml::Predictor$new(mdl, data = tr[, -ncol(tr)], y = tr$Ransomware),
      loss = "ce"
    )$results$importance
  
  H_rf [fold] <- sh_entropy(get_imp(rf$model))
  H_svm[fold] <- sh_entropy(get_imp(svm$model))
  H_enet[fold]<- sh_entropy(get_imp(enet$model))
  H_xgb[fold] <- sh_entropy(get_imp(xgb$model))
  
  # MGM with internal λ-CV
  mgm_df  <- rbind(tr, te); mgm_df$Ransomware <- as.numeric(mgm_df$Ransomware)
  mgm_mat <- jitter_constant(as.matrix(mgm_df), idx_tr)
  mgm_fit <- mgm::mgm(
    data        = mgm_mat[idx_tr, ],
    type        = c(rep("g", ncol(mgm_mat)-1), "c"),
    levels      = c(rep(1, ncol(mgm_mat)-1), 2),
    k           = 2, lambdaSel = "CV", lambdaFolds = 5, ruleReg = "OR"
  )
  mgm_pred <- predict(mgm_fit, mgm_mat[-idx_tr, ])$predicted[, ncol(mgm_mat)]
  mgm_met  <- compute_metrics(
    factor(mgm_pred, levels = c(1,2)),
    factor(mgm_mat[-idx_tr, ncol(mgm_mat)], levels = c(1,2))
  )
  vi_mgm <- abs(mgm_fit$pairwise$wadj[ncol(mgm_fit$pairwise$wadj), -ncol(mgm_fit$pairwise$wadj)])
  H_mgm[fold] <- sh_entropy(vi_mgm)
  
  # Bayesian Network
  bn_tr <- disc_df[idx_tr, ]; bn_te <- disc_df[-idx_tr, ]
  bn_fit <- bnlearn::bn.fit(bnlearn::hc(bn_tr, score = "bic"), bn_tr)
  bn_pred <- predict(bn_fit, node = "Ransomware", data = bn_te, method = "bayes-lw")
  bn_met  <- compute_metrics(bn_pred, bn_te$Ransomware)
  vi_bn   <- get_bn_strengths(bn_fit, bn_tr, "Ransomware")
  H_bn[fold] <- sh_entropy(vi_bn)
  
  # AUTOENCODER: manual 5-fold CV inside 70 %
  inner_folds <- caret::createFolds(seq_len(nrow(tr)), k = 5, list = TRUE)
  best_cv_mse <- Inf; best_hid <- NA_character_
  
  for (nm in names(hidden_grid)) {
    hid <- hidden_grid[[nm]]
    mse_vec <- numeric(length(inner_folds))
    for (k in seq_along(inner_folds)) {
      val_idx <- inner_folds[[k]]; tr_idx <- setdiff(seq_len(nrow(tr)), val_idx)
      hex_tr_i <- as.h2o(tr[tr_idx, -which(names(tr) == "Ransomware")])
      hex_va_i <- as.h2o(tr[val_idx, -which(names(tr) == "Ransomware")])
      ae_tmp <- h2o.deeplearning(
        x               = colnames(hex_tr_i),
        training_frame  = hex_tr_i,
        autoencoder     = TRUE,
        hidden          = hid,
        activation      = "Tanh",
        epochs          = 100,
        seed            = fold + k
      )
      mse_vec[k] <- mean(as.vector(h2o.anomaly(ae_tmp, hex_va_i)))
      # cleanup temp model & frames
      h2o.rm(c(ae_tmp@model_id, h2o.getId(hex_tr_i), h2o.getId(hex_va_i)))
    }
    cv_mse <- mean(mse_vec)
    if (cv_mse < best_cv_mse) { best_cv_mse <- cv_mse; best_hid <- nm }
  }
  
  # retrain AE on full 70 %
  hex_tr_full <- as.h2o(tr[, -which(names(tr) == "Ransomware")])
  best_ae <- h2o.deeplearning(
    x               = colnames(hex_tr_full),
    training_frame  = hex_tr_full,
    autoencoder     = TRUE,
    hidden          = hidden_grid[[best_hid]],
    activation      = "Tanh",
    epochs          = 200,
    seed            = fold
  )
  
  # score outer hold-out
  hex_te <- as.h2o(te[, -which(names(te) == "Ransomware")])
  mse_tr <- as.vector(h2o.anomaly(best_ae, hex_tr_full))
  mse_te <- as.vector(h2o.anomaly(best_ae, hex_te))
  thr    <- quantile(mse_tr, 0.95)
  pred_te<- factor(mse_te > thr, levels = c(FALSE, TRUE))
  ae_met <- compute_metrics(pred_te, te$Ransomware)
  best_arch[fold] <- best_hid
  
  # importance & entropy & parameters for AE
  vi_ae    <- h2o.varimp(best_ae)
  imp_perc <- 100 * vi_ae$percentage
  H_ae[fold] <- sh_entropy(imp_perc)
  P_ae[fold] <- param_count_ae(best_ae)
  ae_imp_all[[fold]] <- data.frame(feature = vi_ae$variable, perc = imp_perc)
  
  # cleanup AE model & frames
  h2o.rm(c(best_ae@model_id, h2o.getId(hex_tr_full), h2o.getId(hex_te)))
  
  # parameter counts for others
  P_rf [fold] <- param_count_rf(rf$model)
  P_svm[fold] <- param_count_svm(svm$model)
  P_enet[fold]<- param_count_enet(enet$model)
  P_xgb[fold] <- param_count_xgb(xgb$model)
  P_mgm[fold] <- param_count_mgm(mgm_fit)
  P_bn [fold] <- param_count_bn(bn_fit)
  
  # efficiency ratios (entropy)
  ratio_rf [fold] <- ratio_entropy(rf$metrics["Accuracy"], H_rf [fold])
  ratio_svm[fold] <- ratio_entropy(svm$metrics["Accuracy"], H_svm[fold])
  ratio_enet[fold]<- ratio_entropy(enet$metrics["Accuracy"],H_enet[fold])
  ratio_xgb[fold] <- ratio_entropy(xgb$metrics["Accuracy"], H_xgb[fold])
  ratio_mgm[fold] <- ratio_entropy(mgm_met["Accuracy"],     H_mgm[fold])
  ratio_bn [fold] <- ratio_entropy(bn_met ["Accuracy"],     H_bn [fold])
  ratio_ae [fold] <- ratio_entropy(ae_met ["Accuracy"],     H_ae [fold])
  
  # efficiency ratios (parameters)
  link_rf  <- H_rf [fold] > eps_small
  link_svm <- H_svm[fold] > eps_small
  link_en  <- H_enet[fold]> eps_small
  link_xgb <- H_xgb[fold] > eps_small
  link_mgm <- sum(vi_mgm)>0
  link_bn  <- sum(vi_bn)>0
  link_ae  <- TRUE
  
  ratioP_rf [fold] <- ratio_params(rf$metrics["Accuracy"],   P_rf [fold], link_rf )
  ratioP_svm[fold] <- ratio_params(svm$metrics["Accuracy"],  P_svm[fold], link_svm)
  ratioP_enet[fold]<- ratio_params(enet$metrics["Accuracy"], P_enet[fold], link_en )
  ratioP_xgb[fold] <- ratio_params(xgb$metrics["Accuracy"],  P_xgb[fold], link_xgb)
  ratioP_mgm[fold] <- ratio_params(mgm_met ["Accuracy"],      P_mgm[fold], link_mgm)
  ratioP_bn [fold] <- ratio_params(bn_met  ["Accuracy"],      P_bn [fold], link_bn )
  ratioP_ae [fold] <- ratio_params(ae_met  ["Accuracy"],      P_ae [fold], link_ae )
  
  # store results
  out[[fold]] <- list(
    rf_model   = rf$model,   rf_metrics  = rf$metrics,
    svm_model  = svm$model,  svm_metrics = svm$metrics,
    enet_model = enet$model, enet_metrics= enet$metrics,
    xgb_model  = xgb$model,  xgb_metrics = xgb$metrics,
    mgm        = mgm_fit,    mgm_metrics = mgm_met,
    bn_fit     = bn_fit,     bn_metrics  = bn_met,
    ae_metrics = ae_met,     ae_imp      = data.frame(feature = vi_ae$variable, perc = imp_perc)
  )
}

cv <- out  # alias downstream

# AE architecture frequency
arch_freq <- sort(table(best_arch), decreasing = TRUE)
print(arch_freq)
cat("Most frequently selected AE architecture:", names(arch_freq)[1], "\n")



######################## 4. EFFICIENCY TABLES & PLOTS #########################
model_names <- c("Random Forest","SVM-RBF","Elastic-Net",
                 "XGBoost","MGM","Bayesian Net","Autoencoder")

df_ratioE <- data.frame(Model = model_names,
                        Mean  = c(mean(ratio_rf), mean(ratio_svm), mean(ratio_enet),
                                  mean(ratio_xgb), mean(ratio_mgm), mean(ratio_bn),
                                  mean(ratio_ae)),
                        SD    = c(sd(ratio_rf), sd(ratio_svm), sd(ratio_enet),
                                  sd(ratio_xgb), sd(ratio_mgm), sd(ratio_bn),
                                  sd(ratio_ae)))
df_ratioE$SE <- df_ratioE$SD / sqrt(outer_folds)
df_ratioE$CI <- qt(0.975, outer_folds - 1) * df_ratioE$SE
df_ratioE$lo <- pmax(df_ratioE$Mean - df_ratioE$CI, 0)
df_ratioE$hi <- df_ratioE$Mean + df_ratioE$CI

df_ratioP <- data.frame(Model = model_names,
                        Mean  = c(mean(ratioP_rf), mean(ratioP_svm), mean(ratioP_enet),
                                  mean(ratioP_xgb), mean(ratioP_mgm), mean(ratioP_bn),
                                  mean(ratioP_ae)),
                        SD    = c(sd(ratioP_rf), sd(ratioP_svm), sd(ratioP_enet),
                                  sd(ratioP_xgb), sd(ratioP_mgm), sd(ratioP_bn),
                                  sd(ratioP_ae)))
df_ratioP$SE <- df_ratioP$SD / sqrt(outer_folds)
df_ratioP$CI <- qt(0.975, outer_folds - 1) * df_ratioP$SE
df_ratioP$lo <- pmax(df_ratioP$Mean - df_ratioP$CI, 0)
df_ratioP$hi <- df_ratioP$Mean + df_ratioP$CI

cat("\n*** Predictive efficiency (Accuracy / Entropy) — mean ± 95 % CI ***\n")
print(knitr::kable(transform(df_ratioE,
                             Value = sprintf("%.3f ± %.3f", Mean, CI))[, c("Model", "Value")],
                   align = "lc"))

cat("\n*** Parameter efficiency (Accuracy / #Parameters) — mean ± 95 % CI ***\n")
print(knitr::kable(transform(df_ratioP,
                             Value = sprintf("%.6f ± %.6f", Mean, CI))[, c("Model", "Value")],
                   align = "lc"))

ggplot(df_ratioE, aes(Model, Mean, fill = Model)) +
  geom_col(colour = "black") +
  geom_errorbar(aes(ymin = lo, ymax = hi), width = .25) +
  labs(title = "Predictive efficiency (Accuracy / Entropy)",
       y = "Accuracy / Entropy", x = NULL) +
  theme_bw(base_size = 14) +
  theme(legend.position = "none",
        axis.text.x = element_text(angle = 15, hjust = 1))

ggplot(df_ratioP, aes(Model, Mean, fill = Model)) +
  geom_col(colour = "black") +
  geom_errorbar(aes(ymin = lo, ymax = hi), width = .25) +
  labs(title = "Parameter efficiency (Accuracy / Parameters)",
       y = "Accuracy / Parameters", x = NULL) +
  theme_bw(base_size = 14) +
  theme(legend.position = "none",
        axis.text.x = element_text(angle = 15, hjust = 1))


######################## 5. CROSS-VALIDATION METRICS ##########################

# shut down H2O once at the end
h2o.shutdown(prompt = FALSE)

mat_rf   <- do.call(rbind, lapply(cv, `[[`, "rf_metrics"))
mat_svm  <- do.call(rbind, lapply(cv, `[[`, "svm_metrics"))
mat_enet <- do.call(rbind, lapply(cv, `[[`, "enet_metrics"))
mat_xgb  <- do.call(rbind, lapply(cv, `[[`, "xgb_metrics"))
mat_mgm  <- do.call(rbind, lapply(cv, `[[`, "mgm_metrics"))
mat_bn   <- do.call(rbind, lapply(cv, `[[`, "bn_metrics"))
mat_ae   <- do.call(rbind, lapply(cv, `[[`, "ae_metrics"))

stat <- function(m) cbind(mean = colMeans(m, na.rm = TRUE),
                          sd   = apply(m, 2, sd, na.rm = TRUE))

rf_st   <- stat(mat_rf);   svm_st  <- stat(mat_svm)
enet_st <- stat(mat_enet); xgb_st  <- stat(mat_xgb)
mgm_st  <- stat(mat_mgm);  bn_st   <- stat(mat_bn)
ae_st   <- stat(mat_ae)

fmt <- function(v, n) sprintf("%.*f ± %.*f", n, v[1], n, v[2])

metrics_tbl <- data.frame(
  Model        = model_names,
  Accuracy     = c(fmt(rf_st["Accuracy", ], 3),  fmt(svm_st["Accuracy", ], 3),
                   fmt(enet_st["Accuracy", ], 3),fmt(xgb_st["Accuracy", ], 3),
                   fmt(mgm_st["Accuracy", ], 3), fmt(bn_st["Accuracy", ], 3),
                   fmt(ae_st ["Accuracy", ], 3)),
  F1           = c(fmt(rf_st["F1", ], 3),  fmt(svm_st["F1", ], 3),
                   fmt(enet_st["F1", ], 3), fmt(xgb_st["F1", ], 3),
                   fmt(mgm_st["F1", ], 3),  fmt(bn_st["F1", ], 3),
                   fmt(ae_st ["F1", ], 3)),
  Matthews_Phi = c(fmt(rf_st["Phi", ], 3),  fmt(svm_st["Phi", ], 3),
                   fmt(enet_st["Phi", ], 3),fmt(xgb_st["Phi", ], 3),
                   fmt(mgm_st["Phi", ], 3), fmt(bn_st["Phi", ], 3),
                   fmt(ae_st ["Phi", ], 3))
)

cat("\n*** Cross-validation metrics (40 × 70 / 30) — mean ± SD ***\n")
print(knitr::kable(metrics_tbl, align = "lccc"))

# ---- helper for CI bar plots -------------------------------------------------
build_tbl <- function(m, s) {
  se <- s / sqrt(outer_folds)
  ci <- qt(0.975, outer_folds - 1) * se
  data.frame(Model = model_names, Mean = m, CI = ci,
             lo = pmax(m - ci, 0), hi = pmin(m + ci, 1))
}

acc_tbl <- build_tbl(c(rf_st["Accuracy", "mean"], svm_st["Accuracy", "mean"],
                       enet_st["Accuracy", "mean"], xgb_st["Accuracy", "mean"],
                       mgm_st["Accuracy", "mean"], bn_st["Accuracy", "mean"],
                       ae_st ["Accuracy", "mean"]),
                     c(rf_st["Accuracy", "sd"],   svm_st["Accuracy", "sd"],
                       enet_st["Accuracy", "sd"], xgb_st["Accuracy", "sd"],
                       mgm_st["Accuracy", "sd"],  bn_st["Accuracy", "sd"],
                       ae_st ["Accuracy", "sd"]))

f1_tbl  <- build_tbl(c(rf_st["F1", "mean"], svm_st["F1", "mean"],
                       enet_st["F1", "mean"], xgb_st["F1", "mean"],
                       mgm_st["F1", "mean"], bn_st["F1", "mean"],
                       ae_st ["F1", "mean"]),
                     c(rf_st["F1", "sd"],   svm_st["F1", "sd"],
                       enet_st["F1", "sd"], xgb_st["F1", "sd"],
                       mgm_st["F1", "sd"],  bn_st["F1", "sd"],
                       ae_st ["F1", "sd"]))

phi_tbl <- build_tbl(c(rf_st["Phi", "mean"], svm_st["Phi", "mean"],
                       enet_st["Phi", "mean"], xgb_st["Phi", "mean"],
                       mgm_st["Phi", "mean"], bn_st["Phi", "mean"],
                       ae_st ["Phi", "mean"]),
                     c(rf_st["Phi", "sd"],   svm_st["Phi", "sd"],
                       enet_st["Phi", "sd"], xgb_st["Phi", "sd"],
                       mgm_st["Phi", "sd"],  bn_st["Phi", "sd"],
                       ae_st ["Phi", "sd"]))

plot_metric <- function(df, title, ylab) {
  ggplot(df, aes(Model, Mean, fill = Model)) +
    geom_col(colour = "black") +
    geom_errorbar(aes(ymin = lo, ymax = hi), width = .25) +
    labs(title = title, y = ylab, x = NULL) +
    theme_bw(base_size = 14) +
    theme(legend.position = "none",
          axis.text.x = element_text(angle = 15, hjust = 1))
}

plot_metric(acc_tbl, "Cross-validated Accuracy (40 folds)", "Accuracy")
plot_metric(f1_tbl,  "Cross-validated F1-score (40 folds)", "F1-score")
plot_metric(phi_tbl, "Cross-validated Matthews φ (40 folds)", "Matthews φ")


###################### 6. VARIABLE IMPORTANCE ACROSS MODELS ###################
summarise_imp <- function(all_df) {
  # mean ± 95 % CI per feature
  feats <- unique(all_df$feature)
  do.call(rbind, lapply(feats, function(fe) {
    vals <- all_df$perc[all_df$feature == fe]
    m <- mean(vals); s <- sd(vals)
    se <- s / sqrt(length(vals)); q <- qt(0.975, length(vals) - 1)
    data.frame(feature = fe, mean = m,
               lo = pmax(m - q*se, 0), hi = pmin(m + q*se, 100))
  }))
}

get_imp_pct <- function(model, data, y) {
  # IMl vanilla feature importance → percentage
  p  <- iml::Predictor$new(model, data = data, y = y)
  fi <- iml::FeatureImp$new(p, loss = "ce")
  agg <- aggregate(importance ~ feature, fi$results, mean)
  data.frame(feature = agg$feature,
             perc = 100*agg$importance / sum(agg$importance))
}

rf_imp_all <- do.call(rbind, lapply(seq_len(outer_folds), function(i)
  get_imp_pct(cv[[i]]$rf_model,
              data_df[, -which(names(data_df) == "Ransomware")],
              data_df$Ransomware)))
rf_imp <- summarise_imp(rf_imp_all); rf_imp$model <- "RF"

svm_imp_all <- do.call(rbind, lapply(seq_len(outer_folds), function(i)
  get_imp_pct(cv[[i]]$svm_model,
              data_df[, -which(names(data_df) == "Ransomware")],
              data_df$Ransomware)))
svm_imp <- summarise_imp(svm_imp_all); svm_imp$model <- "SVM"

enet_imp_all <- do.call(rbind, lapply(seq_len(outer_folds), function(i)
  get_imp_pct(cv[[i]]$enet_model,
              data_df[, -which(names(data_df) == "Ransomware")],
              data_df$Ransomware)))
enet_imp <- summarise_imp(enet_imp_all); enet_imp$model <- "ENet"

xgb_imp_all <- do.call(rbind, lapply(seq_len(outer_folds), function(i)
  get_imp_pct(cv[[i]]$xgb_model,
              data_df[, -which(names(data_df) == "Ransomware")],
              data_df$Ransomware)))
xgb_imp <- summarise_imp(xgb_imp_all); xgb_imp$model <- "XGB"

# ---- MGM importance ---------------------------------------------------------
feat_names <- setdiff(names(data_df), "Ransomware")
p_total    <- ncol(cv[[1]]$mgm$pairwise$wadj)
wadj_list  <- lapply(cv, function(z) z$mgm$pairwise$wadj)
edge_array <- array(unlist(wadj_list), c(p_total, p_total, outer_folds))
resp_idx   <- p_total
edge_mat   <- edge_array[resp_idx, -resp_idx, ]
mgm_df <- data.frame(feature = feat_names,
                     mean   = apply(edge_mat, 1, mean),
                     sd     = apply(edge_mat, 1, sd))
mgm_df$se <- mgm_df$sd / sqrt(outer_folds)
q <- qt(0.975, outer_folds - 1)
mgm_df$lo <- pmax(100*(mgm_df$mean - q*mgm_df$se) / sum(mgm_df$mean), 0)
mgm_df$hi <- pmin(100*(mgm_df$mean + q*mgm_df$se) / sum(mgm_df$mean), 100)
mgm_df$mean <- 100*mgm_df$mean / sum(mgm_df$mean)
mgm_imp <- mgm_df[order(mgm_df$mean), c("feature","mean","lo","hi")]
mgm_imp$model <- "MGM"

# ---- BN importance ----------------------------------------------------------
bn_imp_all <- do.call(rbind, lapply(seq_len(outer_folds), function(i) {
  st <- get_bn_strengths(cv[[i]]$bn_fit, disc_df, "Ransomware")
  if (sum(st) == 0) st[] <- 0
  data.frame(feature = names(st),
             perc = if (sum(st)==0) rep(0,length(st))
             else 100*st / sum(st))
}))
bn_imp <- summarise_imp(bn_imp_all); bn_imp$model <- "BN"

# ---- AE importance ----------------------------------------------------------
ae_imp_df <- do.call(rbind, lapply(seq_len(outer_folds), function(i)
  data.frame(cv[[i]]$ae_imp, fold = i)))
ae_imp <- summarise_imp(ae_imp_df); ae_imp$model <- "AE"

# ---- joint bar plot ---------------------------------------------------------
all_imp <- rbind(rf_imp, svm_imp, enet_imp, xgb_imp,
                 mgm_imp, bn_imp, ae_imp)
ord_feat <- rf_imp$feature[order(rf_imp$mean, decreasing = TRUE)]
all_imp$feature <- factor(all_imp$feature, levels = ord_feat)
all_imp$model   <- factor(all_imp$model,
                          c("RF","SVM","ENet","XGB","MGM","BN","AE"))

ggplot(all_imp, aes(x = mean, y = feature, fill = model)) +
  geom_col(position = position_dodge(.9), colour = "black") +
  geom_errorbarh(aes(xmin = lo, xmax = hi),
                 position = position_dodge(.9), height = .3) +
  labs(title = "Variable importance with 95 % CI",
       x = "Importance (%)", y = NULL) +
  scale_fill_manual(values = c(RF="#6baed6", SVM="#74c476", ENet="#9e9ac8",
                               XGB="#edf8b1", MGM="#fb6a4a", BN="#feb24c",
                               AE="#969696"), name = "Model") +
  theme_bw(base_size = 13) +
  theme(legend.position = "top")


###################### 6 bis NETWORK PLOTS ####################################
library(igraph)
library(tidygraph)
library(ggraph)
library(patchwork)

node_order <- c(feat_names, "Ransomware")

avg_wadj  <- Reduce("+", wadj_list) / length(wadj_list)
graph_mgm <- graph_from_adjacency_matrix(
  avg_wadj, mode = "undirected", weighted = TRUE, diag = FALSE)
V(graph_mgm)$name  <- node_order; V(graph_mgm)$label <- node_order

bn_amat_list <- lapply(cv, function(z) bnlearn::amat(z$bn_fit))
avg_bn_adj   <- Reduce("+", bn_amat_list) / length(bn_amat_list)
graph_bn     <- graph_from_adjacency_matrix(
  avg_bn_adj, mode = "directed", weighted = TRUE, diag = FALSE)
V(graph_bn)$name  <- node_order; V(graph_bn)$label <- node_order

coord_mat <- igraph::layout_in_circle(graph_mgm, order = node_order)
colnames(coord_mat) <- c("x","y")
graph_mgm <- set_vertex_attr(graph_mgm,"x",value=coord_mat[,"x"])
graph_mgm <- set_vertex_attr(graph_mgm,"y",value=coord_mat[,"y"])
graph_bn  <- set_vertex_attr(graph_bn, "x",value=coord_mat[,"x"])
graph_bn  <- set_vertex_attr(graph_bn, "y",value=coord_mat[,"y"])

tg_mgm <- as_tbl_graph(graph_mgm)
tg_bn  <- as_tbl_graph(graph_bn)

p_mgm <- ggraph(tg_mgm, layout = "manual", x = x, y = y) +
  geom_edge_link(aes(edge_width = weight, edge_alpha = weight), show.legend = FALSE) +
  geom_node_point(aes(color = label), size = 5) +
  geom_node_text(aes(label = label), repel = TRUE) +
  theme_void() +
  ggtitle("Average MGM Network")

p_bn <- ggraph(tg_bn, layout = "manual", x = x, y = y) +
  geom_edge_link(aes(edge_width = weight, edge_alpha = weight),
                 arrow = arrow(type = "closed", length = unit(6,"mm")),
                 end_cap = circle(2,"mm"), show.legend = FALSE) +
  geom_node_point(aes(color = label), size = 5) +
  geom_node_text(aes(label = label), repel = TRUE) +
  theme_void() +
  ggtitle("Average BN Network")

(p_mgm + p_bn) + plot_layout(ncol = 2)


################## 7. UNIFIED SPEARMAN FIGURE #################################
rf_sorted <- rf_imp[order(rf_imp$mean, decreasing = TRUE), ]
top5 <- as.character(rf_sorted$feature[1:5])
models <- c("RF","SVM","ENet","XGB","MGM","BN","AE"); m_len <- length(models)

wide_imp <- matrix(NA_real_, nrow = length(top5), ncol = m_len,
                   dimnames = list(top5, models))
for (m in models) for (f in top5)
  wide_imp[f, m] <- all_imp$mean[all_imp$model == m &
                                   all_imp$feature == f]

global_lims <- range(wide_imp, na.rm = TRUE); pad <- diff(global_lims)*.07
global_lims <- c(global_lims[1]-pad, global_lims[2]+pad)
rho_mat <- cor(wide_imp, method = "spearman", use = "pairwise.complete.obs")

feat_pal <- setNames(brewer.pal(length(top5),"Set1"), top5)
zero_mar  <- theme(plot.margin = unit(rep(0,4),"pt"))
diag_theme<- theme_void(base_size = 10) + zero_mar

plot_list <- vector("list", m_len^2); pos <- 1
for (i in seq_len(m_len)) {
  for (j in seq_len(m_len)) {
    if (j < i) {  # lower triangular → rho tile
      rho_val <- rho_mat[i,j]
      plot_list[[pos]] <- ggplot(data.frame(rho=rho_val), aes(1,1,fill=rho)) +
        geom_tile() +
        geom_text(aes(label=sprintf("%.2f",rho)),
                  colour = ifelse(abs(rho_val)>0.5,"white","black"), size = 3) +
        scale_fill_gradient2(low="#d73027", mid="#ffffbf",
                             high="#1a9850", midpoint=0,
                             limits=c(-1,1), guide="none") +
        theme_void() + zero_mar
      pos <- pos+1; next
    }
    if (j == i) {  # diagonal → model label
      plot_list[[pos]] <- ggplot(data.frame(x=0,y=0,label=models[i]),
                                 aes(x,y,label=label)) +
        geom_text(fontface="bold",size = 4) + diag_theme
      pos <- pos+1; next
    }
    # upper triangular → scatter of importances
    df <- data.frame(Feature = factor(rownames(wide_imp), levels = top5),
                     x = wide_imp[, models[i]], y = wide_imp[, models[j]])
    plot_list[[pos]] <- ggplot(df, aes(x,y,colour=Feature)) +
      geom_abline(slope=1, intercept=0, linetype="dashed",
                  linewidth=.4, colour="red") +
      geom_point(size=2.4, alpha=.8) +
      scale_colour_manual(values = feat_pal, name="Feature") +
      scale_x_continuous(limits = global_lims) +
      scale_y_continuous(limits = global_lims) +
      coord_equal(clip="off") +
      labs(x=models[i], y=models[j]) +
      theme_bw(base_size = 8) +
      theme(axis.title = element_text(size=7),
            axis.text  = element_text(size=6)) + zero_mar
    pos <- pos+1
  }
}

one_fig <- wrap_plots(plot_list, ncol = m_len, nrow = m_len,
                      guides = "collect") &
  theme(legend.position="bottom",
        legend.title = element_text(size = 18),
        legend.text  = element_text(size = 18),
        legend.key.height = unit(3.5,"mm"),
        legend.key.width  = unit(3.5,"mm"),
        plot.margin = unit(rep(0,4),"pt")) &
  plot_annotation(title = "Spearman Overview for Top-5 Variable Importances",
                  theme = theme(plot.title = element_text(hjust=.5, size=12),
                                plot.margin = unit(rep(0,4),"pt")))
print(one_fig)


################### 8. PARTIAL-DEPENDENCE PLOTS (PDPs) ########################
show_ci   <- 1L
grid.size <- 40L
response_name <- "Ransomware"
model_tags <- c("RF","SVM","ENet","XGB")
X_ref <- data_df[, setdiff(names(data_df), response_name)]

q_probs <- seq(0,1,length.out = grid.size)
grid_vals <- lapply(X_ref, function(v)
  unique(as.numeric(quantile(v, probs = q_probs, na.rm = TRUE, type = 8))))

clip01 <- function(p) pmin(pmax(p,0),1)
pred_prob <- list(
  RF = function(m,X){ pr <- predict(m$finalModel,data=X)$predictions
  clip01(if(is.matrix(pr)) pr[,"TRUE"]
         else as.numeric(pr=="TRUE")) },
  SVM= function(m,X){ dv <- predict(m$finalModel,X,type="decision")
  if(is.matrix(dv)) dv <- dv[,1]
  clip01(1/(1+exp(-dv))) },
  ENet=function(m,X){ clip01(as.vector(
    predict(m$finalModel,newx=as.matrix(X),
            type="response", s=m$bestTune$lambda))) },
  XGB =function(m,X) clip01(as.numeric(predict(m$finalModel,as.matrix(X))))
)

build_pdp <- function(fun,m,feat){
  if(!is.numeric(X_ref[[feat]])) return(NULL)
  gv <- grid_vals[[feat]]; if(length(gv)<2L) return(NULL)
  p_true <- numeric(length(gv))
  for(i in seq_along(gv)){
    Xtmp <- X_ref; Xtmp[[feat]] <- gv[i]
    p_true[i] <- mean(fun(m,Xtmp))
  }
  data.frame(x=gv, p_true=p_true, p_false=1-p_true)
}

pdp_records <- list()
for(tag in model_tags){
  slot <- switch(tag, RF="rf_model", SVM="svm_model",
                 ENet="enet_model", XGB="xgb_model")
  for(fold in seq_len(outer_folds)){
    m <- cv[[fold]][[slot]]
    if(length(unique(m$trainingData$.outcome))<2L) next
    for(feat in names(X_ref)){
      pdp <- build_pdp(pred_prob[[tag]], m, feat)
      if(is.null(pdp)) next
      pdp$model <- tag; pdp$feature <- feat; pdp$fold <- paste0("Fold-",fold)
      pdp_records[[length(pdp_records)+1L]] <- pdp
    }
  }
}
pdp_all <- do.call(rbind,pdp_records)

agg_rows <- list(); idx <- 1L
for(tag in model_tags){
  for(feat in unique(pdp_all$feature)){
    df <- pdp_all[pdp_all$model==tag & pdp_all$feature==feat,]
    for(cls in c("p_true","p_false")){
      for(xv in sort(unique(df$x))){
        vec <- as.numeric(df[df$x==xv, cls])
        m <- mean(vec); se <- sd(vec)/sqrt(length(vec)); ci <- 1.96*se
        agg_rows[[idx]] <- data.frame(model=tag,feature=feat,
                                      class=ifelse(cls=="p_true","TRUE","FALSE"),
                                      x=xv, mean=m,
                                      lo=clip01(m-ci), hi=clip01(m+ci))
        idx <- idx+1L
      }
    }
  }
}
pdp_ci <- do.call(rbind,agg_rows)
cls_cols <- c("TRUE"="#33a02c","FALSE"="#e31a1c")

plot_pdp <- function(df,target,title,col){
  df <- df[df$class==target,]
  p <- ggplot(df, aes(x,mean))
  if(show_ci==1L)
    p <- p+geom_ribbon(aes(ymin=lo,ymax=hi), fill=col, alpha=.25)
  p+geom_line(colour=col, linewidth=.9) +
    facet_grid(model~feature, scales="free_x") +
    labs(title=title, x="Feature value (quantile grid)", y="Probability") +
    scale_y_continuous(limits=c(0,1)) +
    theme_bw(base_size=11) +
    theme(strip.text.y = element_text(angle=0))
}

print(plot_pdp(pdp_ci,"TRUE",
               "Partial dependence – P(Ransomware = TRUE)", cls_cols["TRUE"]))
print(plot_pdp(pdp_ci,"FALSE",
               "Partial dependence – P(Ransomware = FALSE)", cls_cols["FALSE"]))


###############################################################################
# 9. SIMPLE FAMD ON FULL DATA (numeric predictors + categorical target)
###############################################################################
data_df$Ransomware <- factor(data_df$Ransomware, levels = c(FALSE, TRUE))

famd_res <- FAMD(data_df, ncp = 5, graph = FALSE)

# ---- basic outputs ----------------------------------------------------------
print(famd_res$eig)                 # variance explained per dimension
print(famd_res$var)                 # variable loadings
print(famd_res$ind$coord[1:10, ])   # first 10 individual coords

# ---- quick plots ------------------------------------------------------------
fviz_screeplot(famd_res, addlabels = TRUE)
fviz_famd_var(famd_res, repel = TRUE)


var_df <- as.data.frame(famd_res$var$coord)
var_df$variable <- factor(rownames(var_df), levels = node_order)
p_var <- ggplot(var_df, aes(x = Dim.1, y = Dim.2, color = variable)) +
  geom_point(size = 4) +
  scale_color_hue() +  # default discrete hue palette → matches the network
  labs(
    title = "FAMD Variable Factor Map",
    x     = "Dimension 1",
    y     = "Dimension 2",
    color = "Variable"
  ) +
  theme_minimal(base_size = 12) +
  theme(
    legend.position = "right",
    legend.key.size = unit(5, "mm"),
    legend.title    = element_text(size = 16),
    legend.text     = element_text(size = 14),
    plot.title      = element_text(hjust = 0.5)
  )

print(p_var)
