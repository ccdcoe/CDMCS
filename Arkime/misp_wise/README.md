# MISP to WISE integration

## MISP setup

* https://github.com/MISP/misp-docker

# Set up jupyter notebook

Jupyter notebook is a useful tool for interactive scripting, especially around anything involving interaction with data.

```
apt install python3-pip python3-venv
python3 -m venv /jupyter
source /jupyter/bin/activate
pip install jupyter jupyterlab pandas numpy pymisp
```

```
jupyter lab --no-browser --allow-root --ip 192.168.56.12
```
