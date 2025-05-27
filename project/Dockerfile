# Python 3.12을 베이스로 사용하는 이미지
FROM python:3.12-slim

# 작업 디렉토리 설정
WORKDIR /project

# 패키지 설치용 파일 복사
COPY requirements.txt .

# 패키지 설치
RUN pip install --upgrade pip && pip install -r requirements.txt

# 소스 코드 복사
COPY . .

# 환경변수 설정
ENV FLASK_APP=run.py

# 포트 개방
EXPOSE 5000

# Flask 앱 실행
CMD ["python", "run.py"]
