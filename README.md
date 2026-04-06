Capabilities Overview

Anomaly Detection
Unsupervised Isolation Forest model trained to identify suspicious behavioral patterns without relying on predefined rules.

Data Enrichment
Automatic extraction of IP addresses using Regex, followed by GeoIP API lookups to obtain country, region, and ASN metadata.

Real‑Time Visualization
Interactive Streamlit dashboard featuring:

-Geographic heatmaps
-Time‑based histograms
-Severity metrics
-Critical event tables

Incident Response Support
Events are classified using their Anomaly Score, enabling prioritization of high‑risk threats.

 System Architecture
-Ingestion
 auth.log + ufw.log

-Parsing: Regex → Pandas DataFrame
-Enrichment: GeoIP API
-Normalization: StandardScaler
-Detection: Isolation Forest
-Visualization: Streamlit + Plotly
-Export
 CSV-JSON for SIEM integration

Technology Stack

Language
-Python 3.x

AI - Machine Learning
-Scikit‑Learn Isolation Forest, StandardScaler

Data Processing
-Pandas
-NumPy
-Regex

Geolocation
-Requests GeoIP API

Visualization
-Streamlit
-Plotly
