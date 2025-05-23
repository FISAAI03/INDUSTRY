from flask import Flask
from app.views.cashback import cashback_bp  # <-- 정상 작동하려면 위 조건이 모두 갖춰져야 함

def create_app():
    app = Flask(__name__)
    app.register_blueprint(cashback_bp)  # 블루프린트 등록
    return app