# Phishing URL Scanner

A Flask web app that takes a URL and returns a phishing risk verdict using
a RandomForest model (trained on `dataset.csv`) combined with extra
heuristic checks.

## Setup

```bash
pip install -r requirements.txt
python model_comparison.py   # trains & compares 6 models, saves the best one as model.pkl
python app.py
```

Open http://127.0.0.1:5000 and paste a URL.

## Model comparison & evaluation

`model_comparison.py` trains and evaluates six classifiers on `dataset.csv`:
Logistic Regression, SVM (RBF), Decision Tree, Random Forest, Gradient
Boosting, and KNN. Each one is wrapped in a `StandardScaler` pipeline for
fair comparison.

For every model it computes:
- Accuracy, Precision, Recall, F1 (phishing = positive class)
- ROC-AUC
- 5-fold stratified cross-validation accuracy (mean + std)

Outputs (useful for your project report):
- **`model_comparison_results.csv`** — full metrics table
- **`roc_curves.png`** — ROC curves for all 6 models on one chart
- **`confusion_matrices.png`** — confusion matrix grid for all 6 models
- **`model.pkl`** — the best model by F1-score, automatically used by `app.py`

On the provided dataset, the top models (Decision Tree, Gradient Boosting,
KNN, SVM) all score ~0.98 F1 and ~0.99 ROC-AUC, with Logistic Regression
noticeably weaker (~0.94 F1) — useful evidence for your report that the
relationship between these 7 features and the label isn't strictly linear.

`train_model.py` is kept as a simpler single-model (Random Forest) training
script if you just want a quick baseline without the full comparison.

## How it works

1. **`feature_extractor.py`** — converts a URL into the 7 numeric features
   the model was trained on (`length`, `dots`, `https`, `has_ip`, `has_at`,
   `subdomains`, `suspicious_word`), measured on the domain/authority part
   so long-but-legit paths (e.g. `github.com/org/repo`) don't get penalized.
   It also runs extra "red flag" heuristics that aren't in the training data:
   - IP-address hostnames
   - `@` in the authority (classic cloaking trick)
   - Suspicious/cheap TLDs (`.tk`, `.xyz`, `.top`, etc.)
   - URL shorteners (bit.ly, tinyurl, etc.)
   - No HTTPS
   - Excessive hyphens / subdomains
   - Typosquatting against popular brand names (Levenshtein distance)
   - Non-standard ports

2. **`train_model.py`** — trains a RandomForest (`97.8%` test accuracy on
   the provided dataset) and saves it to `model.pkl`.

3. **`app.py`** — combines the model's probability with the heuristic flag
   count into a hybrid 0-100% risk score:
   - **0-29%** → Likely Safe
   - **30-59%** → Suspicious
   - **60-100%** → Likely Phishing

## Notes / next steps

- The current dataset is small (~920 rows) and only encodes 7 simple
  lexical features. For better real-world accuracy, consider adding columns
  like domain age (WHOIS), SSL certificate validity, and Alexa/Tranco rank,
  then retraining.
- The heuristic layer's brand list (`POPULAR_BRANDS`) and suspicious word
  list (`SUSPICIOUS_WORDS`) in `feature_extractor.py` are easy to extend.
- For production use, run with a real WSGI server (e.g. `gunicorn`) instead
  of the Flask dev server.
