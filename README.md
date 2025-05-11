# whs3_컨테이너 보안 및 운영 - 나만의 앱 배포


## 📁 폴더 구조

```bash
├── app.py # Flask 메인 앱
├── templates/ # HTML 템플릿 폴더
├── static/ # 정적 파일 폴더 (생략 가능)
├── Dockerfile # Docker 이미지 생성 스크립트
├── requirements.txt # Python 의존성 목록
├── deployment.yaml # Kubernetes 배포 설정
└── users.db # SQLite 데이터베이스 파일
```

---

## 🐳 Docker 이미지 빌드 및 실행 방법

### 1. Docker 이미지 빌드

```bash
docker build -t 35_jinhyeonggwon .
```

### 2. Docker 컨테이너 실행 (로컬 테스트)
```bash
docker run -p 5001:5001 35_jinhyeonggwon
앱은 http://localhost:5001 에서 접근할 수 있습니다.
```

### Kubernetes 환경 배포 (Kind 사용)

```bash
1. Kind 클러스터 생성
kind create cluster --name isidoro4

2. Docker 이미지 로드
kind load docker-image 35_jinhyeonggwon --name isidoro4

3. Deployment 적용
kubectl apply -f deployment.yaml

4. Pod 상태 확인
kubectl get pods

5. Pod 로그 확인 (선택)
kubectl logs [POD_NAME]
```

### 배포 이미지 정보

이미지 이름: 35_jinhyeonggwon 

Docker 저장 파일: Releases 탭에서 다운로드
