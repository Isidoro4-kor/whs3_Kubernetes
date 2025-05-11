# 베이스 이미지: 가볍고 Python 3.9 포함
FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 설치 (bcrypt 등 빌드시 필요)
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# requirements.txt 복사 및 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 전체 소스 복사
COPY . .

# 업로드 폴더 미리 생성 (Flask에서 사용하는 폴더)
RUN mkdir -p static/uploads

# 앱이 사용하는 포트
EXPOSE 5001

# 앱 실행 (WSGI 방식으로)
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "app:app"]
