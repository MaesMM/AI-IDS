# NGS-IDS

AI‑IDS is a fun name to showcase and test in a sandbox environment NGS‑IDS (Next Generation Intrusion Detection System), leveraging Machine Learning and Deep Learning.
We create models using **TensorFlow** and plug them to be used with **Snort** thanks to [snortml](https://blog.snort.org/2024/03/talos-launching-new-machine-learning.html).
The repository enables to test and benchmarking the models in a laboratory environment.

The proposed default model is a simple binary text classifier using [HttpsParamsDataset](https://github.com/Morzeux/HttpParamsDataset)


## Installation


```bash
git clone [https://github.com/MaesMM/AI-IDS.git](https://github.com/MaesMM/AI-IDS.git)
cd AI-IDS/lab
docker-compose up
```

Interact with containers : 

```bash
docker exec -it <container> /bin/bash --login
```

Launch snort using a model manually.

<em>In snort container: <em>
```bash 
snort -c /usr/local/snort/etc/snort/snort.lua --talos --lua 'snort_ml_engine = { http_param_model = "/usr/local/snort/etc/snort/docker-volume/snort-http-classifier.model" }; snort_ml = {}; trace = { modules = { snort_ml = {all = 1} } };' -r simulated_sql_injection.pcap
```

## Lab architecture :

![Architecture](Architecture.png)
