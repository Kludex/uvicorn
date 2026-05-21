import logging
import os
from fastapi import FastAPI # Giữ lại FastAPI để minh họa cấu trúc ứng dụng tối thiểu

app = FastAPI()

# Các định tuyến và logic ứng dụng khác của bạn sẽ ở đây
# Ví dụ:
# @app.get("/")
# async def read_root():
#     return {"message": "Hello World"}

# Cấu hình logging để đảm bảo Gunicorn quản lý định dạng nhật ký truy cập.
# Khi Uvicorn chạy như một worker dưới Gunicorn, Gunicorn chịu trách nhiệm
# cho việc ghi nhật ký truy cập, thường được cấu hình thông qua `--access-logformat`.
# Logger truy cập mặc định của Uvicorn (`uvicorn.access`) có thể trùng lặp hoặc
# ghi đè lên cấu hình này, dẫn đến định dạng nhật ký không chính xác hoặc không nhất quán.
# Bằng cách phát hiện Gunicorn qua biến môi trường `GUNICORN_PID`, chúng ta
# tắt logger truy cập của Uvicorn bằng cách đặt mức độ của nó thành CRITICAL.
# Điều này đảm bảo Gunicorn hoàn toàn kiểm soát việc ghi nhật ký truy cập và định dạng của nó.
if "GUNICORN_PID" in os.environ:
    logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)

# Bất kỳ cấu hình logging cụ thể nào khác của ứng dụng có thể đặt ở đây.