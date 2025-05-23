from flask import Flask, render_template, request, redirect, url_for, session, flash
import openai
import os
import pymysql
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

# ✅ OpenAI API 설정
openai.api_key = os.getenv("OPENAI_API_KEY")

# ✅ DB 연결 함수 (MYSQL_URI 사용)
def get_db_connection():
    uri = os.getenv("MYSQL_URI")
    if not uri:
        raise Exception("MYSQL_URI 환경변수가 설정되지 않았습니다.")
    uri = uri.replace("mysql+pymysql://", "mysql://")
    parsed = urlparse(uri)
    return pymysql.connect(
        host=parsed.hostname,
        user=parsed.username,
        password=parsed.password,
        db=parsed.path[1:],  # /dbname → dbname
        port=parsed.port or 3306,
        charset='utf8mb4',
        autocommit=True
    )

# ✅ GPT 응답 함수
def get_openai_advice(prompt):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=300
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"AI 분석 중 오류: {e}"

# ✅ Flask 앱 생성
def create_app():
    app = Flask(__name__, template_folder="app/templates", static_folder="app/static")
    app.secret_key = "your_secret_key"

    # 홈
    @app.route('/')
    def index():
        return render_template("index.html")

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            email = request.form['email']
            username = request.form['username']
            password = request.form['password']
            hashed_pw = generate_password_hash(password)

            conn = get_db_connection()
            cur = conn.cursor()

            # 이메일 중복 체크
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                flash("이미 등록된 이메일입니다.")
                return redirect('/signup')

            # 닉네임 중복 체크
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                flash("이미 존재하는 닉네임입니다.")
                return redirect('/signup')

            # 회원 등록
            cur.execute("""
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
            """, (username, email, hashed_pw))
            conn.close()

            flash("회원가입 완료! 로그인 해주세요.")
            return redirect('/login')

        return render_template("signup.html")

    # 로그인
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')

            if not email or not password:
                flash("이메일과 비밀번호를 모두 입력해주세요.")
                return redirect('/login')

            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT id, username, password_hash FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            conn.close()

            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                flash("로그인 성공")
                return redirect('/')
            else:
                flash("이메일 또는 비밀번호가 올바르지 않습니다.")
                return redirect('/login')

        return render_template("login.html")

    # 로그아웃
    @app.route('/logout')
    def logout():
        session.clear()
        flash("로그아웃되었습니다.")
        return redirect('/')
    
    @app.route('/challenge', methods=['GET', 'POST'])
    def challenge():
        if 'user_id' not in session:
            flash("로그인이 필요합니다.")
            return redirect('/login')

        user_id = session['user_id']
        chart = None
        result = None
        already_participated = False
        latest_entry = None

        import matplotlib.pyplot as plt
        import io, base64
        import pandas as pd
        from datetime import datetime

        conn = get_db_connection()
        cur = conn.cursor()

        # POST 요청이면 사용자가 선택한 월 기준 중복 확인
        if request.method == 'POST':
            year_months = request.form['year_months']
            base = float(request.form['base_usage'])
            usages = float(request.form['usages'])
            save_rate = round(((base - usages) / base) * 100, 2) if base else 0

            # 사용자가 이미 해당 월에 참여했는지 확인
            cur.execute("""
                SELECT id FROM energy_challenges
                WHERE user_id = %s AND year_months = %s
            """, (user_id, year_months))
            if cur.fetchone():
                already_participated = True
                result = f"⚠️ {year_months}에는 이미 참여하셨습니다."
            else:
                # INSERT
                cur.execute("""
                    INSERT INTO energy_challenges (user_id, year_months, usages, base_usage, save_rate)
                    VALUES (%s, %s, %s, %s, %s)
                """, (user_id, year_months, usages, base, save_rate))

                result = f"✅ {year_months} 기준 절약률은 {save_rate}%입니다."
                already_participated = True
                latest_entry = {
                    'year_months': year_months,
                    'usages': usages,
                    'base_usage': base,
                    'save_rate': save_rate
                }

        # 사용자의 가장 최근 참여 정보 가져오기
        cur.execute("""
            SELECT year_months, usages, base_usage, save_rate
            FROM energy_challenges
            WHERE user_id = %s
            ORDER BY year_months DESC
            LIMIT 1
        """, (user_id,))
        row = cur.fetchone()
        if row and not latest_entry:
            already_participated = True
            latest_entry = {
                'year_months': row[0],
                'usages': row[1],
                'base_usage': row[2],
                'save_rate': row[3]
            }
            result = f"📅 최근 참여한 {row[0]} 기준 절약률은 {row[3]}%입니다."

        # ✅ 사용자 절약률 시각화
        cur.execute("""
            SELECT year_months, save_rate
            FROM energy_challenges
            WHERE user_id = %s
            ORDER BY year_months
        """, (user_id,))
        rows = cur.fetchall()
        if rows:
            df = pd.DataFrame(rows, columns=['year_months', 'save_rate'])
            df = df[df['year_months'].str.match(r'^\d{4}-\d{2}$')]
            df['year_months'] = pd.to_datetime(df['year_months'] + '-01', errors='coerce')
            df = df.dropna(subset=['year_months'])

            if not df.empty:
                plt.figure(figsize=(6, 3.5))
                plt.plot(df['year_months'], df['save_rate'], marker='o')
                plt.title('📊 월별 절약률 추이')
                plt.xlabel('월')
                plt.ylabel('절약률 (%)')
                plt.grid(True)
                plt.tight_layout()

                buf = io.BytesIO()
                plt.savefig(buf, format='png')
                buf.seek(0)
                chart = base64.b64encode(buf.read()).decode('utf-8')
                buf.close()
                plt.close()

        # ✅ 절약률 TOP 10 랭킹
        cur.execute("""
            SELECT u.username, e.save_rate
            FROM energy_challenges e
            JOIN users u ON e.user_id = u.id
            WHERE e.year_months = (SELECT MAX(year_months) FROM energy_challenges)
            ORDER BY e.save_rate DESC
            LIMIT 10
        """)
        ranking = [{'username': row[0], 'save_rate': row[1]} for row in cur.fetchall()]

        conn.close()

        return render_template("challenge.html",
                            result=result,
                            chart=chart,
                            ranking=ranking,
                            already_participated=already_participated,
                            latest_entry=latest_entry)

    # 캐시백 컨설팅
    @app.route('/cashback', methods=['GET', 'POST'])
    def cashback():
        if request.method == 'POST':
            base_usage = float(request.form['base_usage'])
            current_usage = float(request.form['current_usage'])
            region = request.form['region']
            building_type = request.form['building_type']
            family_size = int(request.form['family_size'])
            season = request.form['season']

            saved = max(base_usage - current_usage, 0)
            save_rate = round((saved / base_usage) * 100, 2) if base_usage else 0
            cashback = round(saved * 30, 2)

            if save_rate >= 30:
                message = "우수한 절약 실적입니다! 에너지 고효율 가전 구매를 고려해 보세요."
            elif save_rate >= 10:
                message = "절약이 잘 이루어지고 있어요. 사용량 추이를 꾸준히 관리하세요."
            else:
                message = "절약률이 낮습니다. 조명 교체나 사용 패턴 개선을 권장합니다."

            prompt = f"""
당신은 {region}에 거주하는 {building_type} 사용자이며, {family_size}인 가구입니다.
현재 계절은 {season}입니다. 월 평균 전기 사용량은 {current_usage}kWh이며 기준 사용량은 {base_usage}kWh입니다.
절약률은 {save_rate}%, 예상 캐시백은 {cashback}원입니다.

이 조건을 고려하여 추가 절약 전략과 캐시백을 더 많이 받을 수 있는 방법을 제안해주세요.
문장은 최대 3문장 이내로 해주세요.
"""
            gpt_advice = get_openai_advice(prompt)

            return render_template("cashback_result.html",
                                   base_usage=base_usage,
                                   current_usage=current_usage,
                                   save_rate=save_rate,
                                   cashback=cashback,
                                   message=message,
                                   gpt_advice=gpt_advice)

        return render_template("cashback_input.html")

    # AI 기반 진단
    @app.route('/ai-diagnosis', methods=['GET', 'POST'])
    def ai_diagnosis():
        result = None
        if request.method == 'POST':
            region = request.form['region']
            building = request.form['building_type']
            usage = float(request.form['usage'])

            avg_usage = 340
            difference = usage - avg_usage
            rate = round((difference / avg_usage) * 100, 1)

            prompt = f"""
당신은 에너지 절감 전문가입니다. 아래 사용자에게 구체적이고 현실적인 절전 전략을 제시하세요:

- 지역: {region}
- 건물 유형: {building}
- 월 평균 사용량: {usage} kWh
- 지역 평균보다 {abs(rate)}% {'높음' if rate > 0 else '낮음'}

고려할 항목:
- 조명 교체 여부
- 대기전력 차단
- 시간대별 사용 조정
- 냉난방 사용 절감
- 지원금 추천

전략을 항목별로 조언해 주세요.
"""
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": prompt}]
                )
                result = response.choices[0].message.content.strip()
            except Exception as e:
                result = f"AI 분석 중 오류가 발생했습니다: {e}"

        return render_template("ai_diagnosis.html", result=result)

    # 지원금 추천
    @app.route('/support', methods=['GET', 'POST'])
    def support():
        support_result = None
        if request.method == 'POST':
            region = request.form['region']
            actions = request.form.getlist('actions')
            applied = request.form['applied']

            prompt = f"""
당신은 {region}에 거주하며, 다음의 에너지 절감 실천을 하고 있습니다: {', '.join(actions)}.
기존에 신청한 지원금은 {applied}입니다.

현재 정부(산업통상자원부, 환경부 등) 또는 지자체에서 제공하는 에너지 절약 실천자 대상 공공지원금이나 보조금 정보를 추천해 주세요.

조건:
- 거주 지역과 실천 항목 기반으로 맞춤 추천
- 신청 가능 여부와 혜택 중심 설명
- 중복 지원 시 주의사항도 포함
"""

            try:
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": prompt}]
                )
                support_result = response.choices[0].message.content.strip()
            except Exception as e:
                support_result = f"AI 분석 중 오류가 발생했습니다: {e}"

        return render_template("support.html", result=support_result)
    

    return app


