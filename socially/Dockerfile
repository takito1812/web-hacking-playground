FROM python:alpine3.16
WORKDIR /app
COPY requirements.txt /app
RUN pip install -r requirements.txt
RUN echo "flag{y0u_d1d_1t}" > /flag
COPY . /app
ENTRYPOINT ["python"]
CMD ["app.py"]
