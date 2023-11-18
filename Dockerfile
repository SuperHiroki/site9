# Pythonのイメージを取得
FROM python:3.9

# ワーキングディレクトリを設定
WORKDIR /site9

# 必要なパッケージをインストール
ADD requirements.txt .
RUN pip install -r requirements.txt

# ソースを追加
ADD . .

CMD [ "python", "./app.py" ]

