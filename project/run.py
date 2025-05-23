from main import create_app  # ← app이 아니라 main에서 import

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
