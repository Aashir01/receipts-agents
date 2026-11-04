# Browser sandbox image: headless Chromium driven by a fixed-vocabulary driver.
# Runs under gVisor on a Docker network whose only exit is the per-task egress proxy.
FROM python:3.12-slim
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN pip install --no-cache-dir playwright \
    && playwright install --with-deps chromium \
    && useradd -m -u 1000 browser \
    && chmod -R a+rX /ms-playwright
COPY driver.py /opt/driver.py
USER browser
WORKDIR /work
CMD ["python", "-u", "/opt/driver.py"]
