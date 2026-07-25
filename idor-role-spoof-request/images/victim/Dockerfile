FROM python:3.11-slim
WORKDIR /app
COPY source/app.py /app/app.py
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
ARG FLAG
ENV FLAG=${FLAG}
EXPOSE 5000
CMD ["python", "app.py"]
