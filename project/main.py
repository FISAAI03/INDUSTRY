from flask import Flask, render_template, request, redirect, url_for, session, flash
import openai
import os
import pymysql
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import random

app = Flask(__name__)
app.secret_key = "your_secret"
oauth = OAuth(app)
KAKAO_CLIENT_ID = os.getenv("KAKAO_CLIENT_ID")

def get_avg_usage_from_kepco(region, year, month):
    api_key = os.getenv("KEPCO_API_KEY")
    metroCd_map = {
                '서울특별시': '11', '부산광역시': '26', '대구광역시': '27',
                '인천광역시': '28', '광주광역시': '29', '대전광역시': '30',
                '울산광역시': '31', '경기도': '41', '강원도': '42',
                '충청북도': '43', '충청남도': '44', '전라북도': '45',
                '전라남도': '46', '경상북도': '47', '경상남도': '48',
                '제주특별자치도': '50'
            }

    metroCd = metroCd_map.get(region)
    if not metroCd:
        return None

    url = "https://bigdata.kepco.co.kr/openapi/v1/powerUsage/houseAve.do"
    params = {
        "year": year,
        "month": month,
        "metroCd": metroCd,
        "apiKey": api_key,
        "returnType": "json"
    }

    try:
        res = requests.get(url, params=params)
        data = res.json().get("data", [])
        if data and 'powerUsage' in data[0]:
            return float(data[0]['powerUsage'])
    except Exception as e:
        print("KEPCO API 오류:", e)

    return None

def get_avg_usage_from_kepco(region, year, month):
    api_key = os.getenv("KEPCO_API_KEY")  # 환경변수에서 API 키 가져오기
    metroCd_map = {
                '서울특별시': '11', '부산광역시': '26', '대구광역시': '27',
                '인천광역시': '28', '광주광역시': '29', '대전광역시': '30',
                '울산광역시': '31', '경기도': '41', '강원도': '42',
                '충청북도': '43', '충청남도': '44', '전라북도': '45',
                '전라남도': '46', '경상북도': '47', '경상남도': '48',
                '제주특별자치도': '50'
            }

    metroCd = metroCd_map.get(region)
    if not metroCd:
        return None  # 해당 지역 없음

    url = "https://bigdata.kepco.co.kr/openapi/v1/powerUsage/houseAve.do"
    params = {
        "year": year,
        "month": month,
        "metroCd": metroCd,
        "apiKey": api_key,
        "returnType": "json"
    }

    try:
        res = requests.get(url, params=params)
        data = res.json().get("data", [])
        if data:
            avg_usage = float(data[0]['powerUsage'])
            return avg_usage
    except Exception as e:
        print("KEPCO API 오류:", e)

    return None

oauth.register(
    name='kakao',
    client_id=os.getenv('KAKAO_CLIENT_ID'),
    access_token_url='https://kauth.kakao.com/oauth/token',
    access_token_params=None,
    authorize_url='https://kauth.kakao.com/oauth/authorize',
    authorize_params=None,
    api_base_url='https://kapi.kakao.com/v2/',
    client_kwargs={'scope': 'profile_nickname account_email'}
)

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
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM energy_challenges")
        challenge_count = cur.fetchone()[0]
        conn.close()

        return render_template('index.html', challenge_count=challenge_count)



    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        conn = get_db_connection()
        cur = conn.cursor()

        # 지역 목록 불러오기
        cur.execute("SELECT name FROM regions ORDER BY name")
        regions = [row[0] for row in cur.fetchall()]

        if request.method == 'POST':
            email = request.form['email']
            username = request.form['username']
            password = request.form['password']
            region = request.form['region']
            building_type = request.form['building_type']
            household_size = int(request.form['household_size'])

            hashed_pw = generate_password_hash(password)

            # 이메일 중복 체크
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                flash("이미 등록된 이메일입니다.")
                conn.close()
                return redirect('/signup')

            # 닉네임 중복 체크
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                flash("이미 존재하는 닉네임입니다.")
                conn.close()
                return redirect('/signup')

            # 사용자 등록
            cur.execute("""
                INSERT INTO users (username, email, password_hash, region, building_type, household_size)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, email, hashed_pw, region, building_type, household_size))

            conn.commit()
            conn.close()

            flash("회원가입 완료! 로그인 해주세요.")
            return redirect('/login')

        conn.close()
        return render_template("signup.html", regions=regions)

    
    @app.route('/kakao/additional', methods=['GET', 'POST'])
    def kakao_additional():
        if request.method == 'POST':
            username = request.form['username']
            region = request.form['region']
            building_type = request.form['building_type']
            household_size = int(request.form['household_size'])
            email = session.get('pending_email')  # 카카오 콜백에서 저장한 값
            kakao_id = session.get('pending_id')

            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO users (id, username, email, password_hash, region, building_type, household_size)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (kakao_id, username, email, 'kakao_oauth', region, building_type, household_size))

            session['user_id'] = kakao_id
            session['username'] = username
            session.pop('pending_email', None)
            session.pop('pending_id', None)

            flash("카카오 로그인 + 정보 등록 완료!")
            return redirect('/')

        return render_template("kakao_additional.html")

    @app.route('/login/kakao')
    def login_kakao():
        redirect_uri = url_for('kakao_callback', _external=True)
        return oauth.kakao.authorize_redirect(redirect_uri)

    @app.route('/login/kakao/callback')
    def kakao_callback():
        token = oauth.kakao.authorize_access_token()
        resp = oauth.kakao.get('user/me')
        profile = resp.json()

        kakao_id = profile['id']
        email = profile['kakao_account'].get('email')
        nickname = profile['kakao_account']['profile']['nickname']

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id, username FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash("카카오 로그인 성공!")
            return redirect('/')
        else:
            session['pending_email'] = email
            session['pending_id'] = kakao_id
            return redirect('/kakao/additional')


    @app.route('/check-email', methods=['POST'])
    def check_email():
        email = request.json.get('email')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        exists = cur.fetchone() is not None
        conn.close()
        return {'exists': exists}

    @app.route('/check-username', methods=['POST'])
    def check_username():
        username = request.json.get('username')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        exists = cur.fetchone() is not None
        conn.close()
        return {'exists': exists}


    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')

            conn = get_db_connection()
            cur = conn.cursor()

            # is_admin 필드도 함께 조회
            cur.execute("SELECT id, username, password_hash, is_admin FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            conn.close()

            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['is_admin'] = user[3]  # ✅ 여기가 핵심
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

        current_month = datetime.today().strftime('%Y-%m')  # ⬅️ 현재 년-월 문자열

        conn = get_db_connection()
        cur = conn.cursor()

        # POST 요청이면 사용자가 선택한 월 기준 중복 확인
        if request.method == 'POST':
            year_months = request.form['year_months']
            base = float(request.form['base_usage'])
            usages = float(request.form['usages'])
            save_rate = round(((base - usages) / base) * 100, 2) if base else 0

            # 중복 여부 확인
            cur.execute("SELECT id FROM energy_challenges WHERE user_id = %s AND year_months = %s", (user_id, year_months))
            if cur.fetchone():
                already_participated = True
                result = f"⚠️ {year_months}에는 이미 참여하셨습니다."
            else:
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

        # 가장 최근 참여 정보 조회
        if not latest_entry:
            cur.execute("""
                SELECT year_months, usages, base_usage, save_rate
                FROM energy_challenges
                WHERE user_id = %s
                ORDER BY year_months DESC
                LIMIT 1
            """, (user_id,))
            row = cur.fetchone()
            if row:
                already_participated = True
                latest_entry = {
                    'year_months': row[0],
                    'usages': row[1],
                    'base_usage': row[2],
                    'save_rate': row[3]
                }
                result = f"📅 최근 참여한 {row[0]} 기준 절약률은 {row[3]}%입니다."

        # 사용자 절약률 그래프
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

        # TOP 10
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
                            latest_entry=latest_entry,
                            current_month=current_month)  # ⬅️ 현재 월을 템플릿으로 전달
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

    @app.route('/ai-diagnosis', methods=['GET', 'POST'])
    def ai_diagnosis():
        result = None
        breakdown = None
        rate = None

        if 'user_id' not in session:
            flash("로그인이 필요합니다.")
            return redirect('/login')

        conn = get_db_connection()
        cur = conn.cursor()

        user_id = session['user_id']
        cur.execute("SELECT region, building_type, household_size FROM users WHERE id = %s", (user_id,))
        user_info = cur.fetchone()
        if not user_info:
            flash("사용자 정보를 불러올 수 없습니다.")
            return redirect('/')

        region, building_type, household_size = user_info

        if request.method == 'POST':
            usage = float(request.form['usage'])

            # ✅ 지역 코드 매핑
            region_code_map = {
                '서울특별시': '11', '부산광역시': '26', '대구광역시': '27',
                '인천광역시': '28', '광주광역시': '29', '대전광역시': '30',
                '울산광역시': '31', '경기도': '41', '강원도': '42',
                '충청북도': '43', '충청남도': '44', '전라북도': '45',
                '전라남도': '46', '경상북도': '47', '경상남도': '48',
                '제주특별자치도': '50'
            }

            metroCd = region_code_map.get(region, '11')  # 기본값: 서울
            year = datetime.today().strftime('%Y')
            month = datetime.today().strftime('%m')
            api_key = os.getenv('KEPCO_API_KEY')

            kepco_url = "https://bigdata.kepco.co.kr/openapi/v1/powerUsage/houseAve.do"
            params = {
                'year': year,
                'month': month,
                'metroCd': metroCd,
                'apiKey': api_key,
                'returnType': 'json'
            }

            # ✅ KEPCO API 호출
            try:
                import requests
                response = requests.get(kepco_url, params=params, timeout=5)
                data = response.json()
                avg_usage = float(data['data'][0]['powerUsage'])
            except Exception as e:
                avg_usage = 340  # Fallback
                print("한전 API 호출 실패:", e)

            # ✅ 분석 수치 계산
            difference = usage - avg_usage
            rate = round((difference / avg_usage) * 100, 1)

            # ✅ 프롬프트 구성
            prompt = f"""
    당신은 에너지 절약 컨설턴트입니다.

    사용자 정보:
    - 지역: {region}
    - 건물 유형: {building_type}
    - 가구원 수: {household_size}
    - 월 평균 사용량: {usage} kWh
    - 지역 평균 사용량: {avg_usage} kWh ({'+' if rate > 0 else ''}{rate}% {'높음' if rate > 0 else '낮음'})

    위 정보를 바탕으로 개인 맞춤형 에너지 절약 전략을 다음 항목 중심으로 제시해주세요:
    - 조명
    - 대기전력
    - 시간대별 전력소비 습관
    - 냉난방 사용 습관
    - 지역 맞춤 지원금 정보

    형식은 마크다운 없이 자연어 문장으로 구성된 하나의 문단으로 출력해주세요.
            """

            try:
                import openai
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": prompt}]
                )
                result = response.choices[0].message.content.strip()

                # DB 저장
                cur.execute("""
                    INSERT INTO ai_diagnosis_results (user_id, region, building_type, household_size, usages, result, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (user_id, region, building_type, household_size, usage, result))
                conn.commit()

            except Exception as e:
                result = f"AI 분석 중 오류가 발생했습니다: {e}"

        conn.close()
        return render_template(
            "ai_diagnosis.html",
            result=result,
            region=region,
            building_type=building_type,
            rate=rate
        )

    
    

    @app.route('/contact')
    def contact():
        if 'user_id' not in session:
            flash("로그인이 필요합니다.")
            return redirect('/login')

        user_id = session['user_id']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM inquiries
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))
        rows = cur.fetchall()
        conn.close()

        return render_template("contact.html", rows=rows)


    @app.route('/contact/write', methods=['GET', 'POST'])
    def contact_write():
        if 'user_id' not in session:
            flash("로그인이 필요합니다.")
            return redirect('/login')

        user_id = session['user_id']
        username = session.get('username')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        email = user[0] if user else ''

        if request.method == 'POST':
            message = request.form['message']
            cur.execute("""
                INSERT INTO inquiries (user_id, name, email, message)
                VALUES (%s, %s, %s, %s)
            """, (user_id, username, email, message))
            conn.commit()
            conn.close()
            flash("문의가 정상적으로 접수되었습니다.")
            return redirect('/contact')

        conn.close()
        return render_template("contact_write.html", user_email=email)


    @app.route('/admin/inquiries', methods=['GET', 'POST'])
    def admin_inquiries_view():
        if not session.get('is_admin'):
            flash("관리자만 접근 가능합니다.")
            return redirect('/')

        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == 'POST':
            inquiry_id = request.form['inquiry_id']
            answer = request.form['answer']
            cur.execute("""
                UPDATE inquiries
                SET answer = %s, answered_at = NOW()
                WHERE id = %s
            """, (answer, inquiry_id))
            conn.commit()

        cur.execute("SELECT * FROM inquiries ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()

        return render_template("admin_inquiries.html", rows=rows)


    @app.route('/support', methods=['GET', 'POST'])
    def support():
        conn = get_db_connection()
        cur = conn.cursor()

        # 지역 목록 가져오기
        cur.execute("SELECT name FROM regions ORDER BY name")
        regions = [row[0] for row in cur.fetchall()]

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

        conn.close()
        return render_template("support.html", result=support_result, regions=regions)

        

    return app


