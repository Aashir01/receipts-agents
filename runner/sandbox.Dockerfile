# Image every sandboxed job runs in. The sandbox has no network,
# so all libraries the agent may use are baked in here.
FROM python:3.12-slim

RUN pip install --no-cache-dir \
        pandas numpy matplotlib seaborn scipy openpyxl tabulate \
    && useradd -m -u 1000 sandbox \
    && python -c "import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot"

USER sandbox
WORKDIR /work
