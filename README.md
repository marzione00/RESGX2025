# Repository Overview - Ransomware detection using sample entropy and graphical models: a methodology for explainable artificial intelligence (XAI) in cybersecurity

This repository contains **(i)** the dataset provided by *Anand, P. Mohan; Charan, P. V. Sai; and Shukla, Sandeep K.* for **“HiPeR — Early detection of a ransomware attack using hardware performance counters”**, and **(ii)** the code used in our article/experiments built on top of that dataset.

## Required citation for dataset use
If you use the **HiPeR** dataset in any form (including subsets, derivatives, or re-distributions), **you must cite the original article** by the dataset authors:

ANAND, P. Mohan; CHARAN, PV Sai; SHUKLA, Sandeep K. Hiper-early detection of a ransomware attack using hardware performance counters. Digital Threats: Research and Practice, 2023, 4.3: 1-24. https://dl.acm.org/doi/10.1145/3608484

# Abstract

Malware detection poses a critical challenge for both society and Business and Industry (B&I), particularly given the necessity for secure digital transformation. Among various cybersecurity threats, ransomware has emerged as especially disruptive, capable of halting operations, interrupting business continuity, and causing significant financial damage. Recent research has increasingly leveraged machine learning techniques to detect ransomware using Hardware Performance Counters (HPCs)—special CPU registers that track low-level hardware activities.In this study, we first propose a Sample Entropy-based method for compressing HPC time series data. This method effectively reduces dimensionality while preserving essential behavioral patterns, thus making it particularly suitable for practical B&I scenarios where accuracy and computational efficiency are crucial. Secondly, we investigate explainable machine learning algorithms for ransomware detection in B&I contexts, emphasizing transparency and interpretability. To achieve this goal, we focus on graphical models, specifically Markov Random Fields and Bayesian Networks. We evaluate the performance of these explainable methods against a baseline comprising Elastic Net, Support Vector Machines (SVM) with a radial kernel, XGBoost, and Autoencoder models. Our results demonstrate that these graphical models provide consistent and interpretable outcomes, closely aligned with known ransomware behaviors.

