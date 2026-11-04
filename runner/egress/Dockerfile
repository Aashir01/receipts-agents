# Per-task egress proxy: the browser sandbox's only route to the internet.
FROM python:3.12-slim
COPY proxy.py /opt/proxy.py
USER 65534:65534
EXPOSE 8888
CMD ["python", "-u", "/opt/proxy.py"]
