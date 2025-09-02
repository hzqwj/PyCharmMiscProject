from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
import mysql.connector
from mysql.connector import Error
from cryptography.fernet import Fernet
from fastapi.staticfiles import StaticFiles
from typing import List, Optional
from fastapi.middleware.cors import CORSMiddleware
import requests
from fastapi import File, UploadFile
import shutil
import uuid
from pathlib import Path
from fastapi import Body
# 在代码开头添加
print("MYSQL_HOST:", os.getenv("MYSQL_HOST"))
print("MYSQL_PORT:", os.getenv("MYSQL_PORT"))
# 从环境变量获取数据库配置和密钥
DB_HOST = os.getenv("MYSQL_HOST")
DB_PORT = os.getenv("MYSQL_PORT")
DB_NAME = os.getenv("MYSQL_DATABASE_NAME")
DB_USER = os.getenv("MYSQL_USERNAME")
DB_PASSWORD = os.getenv("MYSQL_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# 修正AI服务配置
AI_MODEL_URL = os.getenv("AI_MODEL_URL", "http://localhost:8001/chat")
AI_MODEL_API_KEY = os.getenv("AI_MODEL_API_KEY", "default-api-key")
# 在数据库配置加载后，app初始化前
try:
    # 测试连接
    test_conn = mysql.connector.connect(
        host=DB_HOST,
        port=int(DB_PORT),
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    test_conn.close()
    print("数据库连接测试成功")
except Error as e:
    print(f"数据库连接测试失败: {str(e)}")
    # 可选：直接退出应用，因为数据库连接是核心依赖
    # import sys
    # sys.exit(1)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
AVATAR_DIR = os.path.join(STATIC_DIR, "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)  # 确保static目录存在
if not os.access(AVATAR_DIR, os.W_OK):
    raise RuntimeError(f"上传目录 {AVATAR_DIR} 没有写入权限，请检查服务器配置")
app = FastAPI()
# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# 密码哈希和验证
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 加密密钥
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)
# 在 get_db_connection 函数附近添加
print("MYSQL_HOST 的值：", os.getenv("MYSQL_HOST"))
# 数据库连接函数
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            port=int(DB_PORT),
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        if not connection.is_connected():
            raise Error("数据库连接未建立")
        return connection
    except Error as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库连接错误: {str(e)}"
        )


# 用户模型
class User(BaseModel):
    id: int
    username: str
    role: str
    role_id: int
    avatar: Optional[str] = None
    name: Optional[str] = None  # 新增姓名字段
    email: Optional[str] = None  # 新增邮箱字段
class UserInDB(User):
    password_hash: str
    salt: str | None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str = None

class Permission(BaseModel):
    resource: str
    action: str

class EncryptedData(BaseModel):
    data: str

class Role(BaseModel):
    id: int
    name: str
    description: str

class MenuItem(BaseModel):
    id: int
    name: str
    path: str
    icon: str
    sort_order: int

class ChatSession(BaseModel):
    id: int
    title: str
    created_at: datetime

class ChatMessage(BaseModel):
    id: int
    session_id: int
    role: str
    content: str
    created_at: datetime
class UserCreate(BaseModel):
    username: str
    password: str
    confirmpassword:str
class PasswordReset(BaseModel):
    username: str
    new_password: str
    confirm_new_password:str
class PasswordUpdateRequest(BaseModel):
    old_password: str
    new_password: str
class ChatRequest(BaseModel):
    message: str
    session_id: Optional[int] = None
    history: Optional[List[dict]] = None  # 添加历史消息字段
# 认证相关函数
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    # 生成哈希值
    hashed = pwd_context.hash(password)
    return hashed
print(pwd_context.hash("user@123"))
def get_user(username: str):
    print('接受的用户：',username)
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT u.*, r.name as role 
        FROM users u 
        JOIN roles r ON u.role_id = r.id 
        WHERE u.username = %s
    """, (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        print("用户名正确")
        try:
            user_obj = UserInDB(** user)
            print("UserInDB实例创建成功")  # 若不打印，说明此处抛异常
            return user_obj
        except Exception as e:
            print(f"创建UserInDB实例失败: {e}")  # 打印具体错误
            raise  # 抛出异常让上层感知
        return UserInDB(**user)
    print("用户名不正确")
    return None


def authenticate_user(username: str, password: str):
    print(f"接收的密码：{password}")
    try:
        # 1. 正确获取连接和游标
        conn = get_db_connection()
        cursor = conn.cursor()
        # 2. 执行查询后必须读取结果
        cursor.execute("SELECT 1")
        cursor.fetchone()  # 读取结果，避免未读数据残留
        print("数据库连接正常")
        # 3. 及时关闭游标和连接
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"数据库连接失败: {e}")
    print("456")
    user = get_user(username)
    print("123")
    if not user:
        print(f"用户名错误：输入的 '{username}' 在数据库中不存在")
        return False
    if not verify_password(password, user.password_hash):
        print(f"密码错误：输入的密码与用户 '{username}' 的密码不匹配")
        return False
    print(f"验证成功：用户名 '{username}' 和密码均正确")
    # 更新最后登录时间
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user.id,))
    conn.commit()
    cursor.close()
    conn.close()

    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# 路由
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "user_id": user.id},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# 修改用户信息查询接口（确保返回name和email）
@app.get("/users/me", response_model=User)
async def read_user_me(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT u.id, u.username, u.name, u.email, u.avatar, 
                   r.name as role, u.role_id 
            FROM users u 
            JOIN roles r ON u.role_id = r.id 
            WHERE u.id = %s
        """, (current_user.id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="用户不存在")
        return user

    finally:
        cursor.close()
        conn.close()

@app.put("/users/my", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/users/me/last-login")
async def get_last_login(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT last_login FROM users WHERE id = %s", (current_user.id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return {"last_login": result["last_login"]}


@app.get("/roles", response_model=List[Role])
async def get_roles(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, description FROM roles")
    roles = cursor.fetchall()
    cursor.close()
    conn.close()
    return roles


@app.get("/menu-items", response_model=List[MenuItem])
async def get_menu_items(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, path, icon, sort_order FROM menu_items ORDER BY sort_order")
    menus = cursor.fetchall()
    cursor.close()
    conn.close()
    return menus


@app.post("/encrypt")
async def encrypt_data(data: EncryptedData, current_user: User = Depends(get_current_user)):
    try:
        encrypted_data = cipher_suite.encrypt(data.data.encode())
        # 先返回加密数据，然后异步记录日志（避免日志记录失败影响加密）
        response = {"encrypted_data": encrypted_data.decode()}
        # 异步记录日志（使用后台任务或线程）
        await log_operation(current_user.id, 'encrypt')
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"加密失败: {str(e)}")

async def log_operation(user_id: int, action: str):
    """异步记录操作日志"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO operation_logs (user_id, action) VALUES (%s, %s)", (user_id, action))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        print(f"日志记录失败: {e}")  # 打印日志，但不影响主操作


@app.post("/decrypt")
async def decrypt_data(data: EncryptedData, current_user: User = Depends(get_current_user)):
    try:
        decrypted_data = cipher_suite.decrypt(data.data.encode())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO operation_logs (user_id, action) VALUES (%s, 'decrypt')", (current_user.id,))
        conn.commit()
        cursor.close()
        conn.close()
        return {"decrypted_data": decrypted_data.decode()}
    except:
        raise HTTPException(status_code=400, detail="解密失败")


# 权限管理路由
@app.get("/permissions")
async def get_user_permissions(username: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="权限不足")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.resource, p.action 
        FROM permissions p 
        JOIN users u ON p.user_id = u.id 
        WHERE u.username = %s
    """, (username,))
    permissions = cursor.fetchall()
    cursor.close()
    conn.close()
    return permissions

@app.post("/permissions")
async def assign_permission(username: str, permission: Permission, current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="权限不足")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # 1. 修正 SQL：查询用户 ID（主键），而非 role_id
        cursor.execute("SELECT role_id FROM users WHERE username = %s", (username,))
        user_record = cursor.fetchone()
        # 2. 校验用户存在性
        if not user_record:
            raise HTTPException(status_code=404, detail="用户不存在")
        user_id = user_record[0]  # 用索引 0 取结果
        print("当前user_id:",user_id)  # 现在会执行（前面已处理 None 情况）
        # 3. 分配权限（SQL 已修正 created_at）
        cursor.execute("""  
            INSERT INTO permissions (user_id, resource, action, created_at)  
            VALUES (%s, %s, %s, NOW())  
        """, (user_id, permission.resource, permission.action))
        conn.commit()
        return {"message": "权限分配成功"}
    # 4. 完善异常捕获：先抓业务错误，再抓数据库异常，最后抓通用异常
    except HTTPException as e:  # 主动抛出的 HTTP 异常（如用户不存在）
        conn.rollback()
        raise e  # 直接抛出，保持状态码和信息
    except Error as e:  # 数据库操作错误（如唯一约束冲突）
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # 其他 Python 异常（如代码逻辑错误）
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"系统错误：{str(e)}")
    finally:
        cursor.close()
        conn.close()

# 聊天功能路由
@app.post("/chat/sessions")
async def create_chat_session(title: str, current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO chat_sessions (user_id, title) VALUES (%s, %s)",
            (current_user.id, title)
        )
        session_id = cursor.lastrowid
        conn.commit()
        return {"session_id": session_id}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()

# 修改后的 /chat/messages 接口
@app.post("/chat/messages")
async def send_message(request: ChatRequest, current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # 创建新会话（如果不存在）
        if not request.session_id:
            cursor.execute(
                "INSERT INTO chat_sessions (user_id, title, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                (current_user.id, request.message[:50] + "...")
            )
            request.session_id = cursor.lastrowid

        # 保存用户消息
        cursor.execute(
            "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (%s, %s, %s, NOW())",
            (request.session_id, "user", request.message)
        )
        user_message_id = cursor.lastrowid

        # 获取当前会话的历史消息（最多10条）
        cursor.execute(
            """
            SELECT role, content 
            FROM chat_messages 
            WHERE session_id = %s 
            ORDER BY created_at DESC 
            LIMIT 10
            """,
            (request.session_id,)
        )
        history_messages = cursor.fetchall()
        history_messages.reverse()  # 按时间正序排列
        history = [{"role": msg[0], "content": msg[1]} for msg in history_messages]

        # 调用大模型API
        ai_response = "抱歉，我暂时无法回答这个问题。"  # 默认回复
        try:
            headers = {"Authorization": f"Bearer {AI_MODEL_API_KEY}"}
            payload = {
                "message": request.message,
                "history": history
            }
            response = requests.post(AI_MODEL_URL, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            ai_response = response.json().get("response", "AI服务暂不可用")
        except Exception as e:
            print(f"AI模型调用失败：URL={AI_MODEL_URL}，错误={str(e)}")  # 查看日志
            ai_response = "抱歉，AI服务暂不可用，请稍后重试"

        # 保存AI回复
        cursor.execute(
            "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (%s, %s, %s, NOW())",
            (request.session_id, "assistant", ai_response)
        )
        ai_message_id = cursor.lastrowid

        # 只更新会话时间，不再更新last_message字段
        cursor.execute(
            "UPDATE chat_sessions SET updated_at = NOW() WHERE id = %s",
            (request.session_id,)
        )

        conn.commit()
        return {
            "response": ai_response,
            "session_id": request.session_id,
            "user_message_id": user_message_id,
            "ai_message_id": ai_message_id
        }
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()

# 修改获取会话列表接口
@app.get("/chat/sessions", response_model=List[ChatSession])
async def get_chat_sessions(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """SELECT s.id, s.title, s.created_at, s.updated_at,
                  m.content as last_message, m.role as last_message_role
           FROM chat_sessions s
           LEFT JOIN (
               SELECT session_id, content, role, created_at
               FROM chat_messages
               WHERE id IN (
                   SELECT MAX(id) FROM chat_messages GROUP BY session_id
               )
           ) m ON s.id = m.session_id
           WHERE s.user_id = %s 
           ORDER BY s.updated_at DESC""",
        (current_user.id,)
    )
    sessions = cursor.fetchall()
    cursor.close()
    conn.close()
    return sessions

@app.get("/chat/sessions/{session_id}/messages", response_model=List[ChatMessage])
async def get_chat_messages(session_id: int,page: int = 1,page_size: int = 20, current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # 验证会话属于当前用户
    cursor.execute(
        "SELECT user_id FROM chat_sessions WHERE id = %s",
        (session_id,)
    )
    session = cursor.fetchone()
    if not session or session["user_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="无权访问此会话")
    offset = (page - 1) * page_size
    cursor.execute(
        """SELECT id, session_id, role, content, created_at 
           FROM chat_messages 
           WHERE session_id = %s 
           ORDER BY created_at ASC
           LIMIT %s OFFSET %s""",
        (session_id, page_size, offset)
    )
    messages = cursor.fetchall()
    cursor.close()
    conn.close()
    return messages

# 新增编辑会话标题接口
@app.put("/chat/sessions/{session_id}")
async def update_chat_session(
    session_id: int,
    title: str = Body(..., embed=True),  # 从请求体获取新标题
    current_user: User = Depends(get_current_user)
):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # 验证会话归属
        cursor.execute(
            "SELECT user_id FROM chat_sessions WHERE id = %s",
            (session_id,)
        )
        session = cursor.fetchone()
        if not session or session["user_id"] != current_user.id:
            raise HTTPException(status_code=403, detail="无权访问此会话")

        # 更新标题
        cursor.execute(
            "UPDATE chat_sessions SET title = %s, updated_at = NOW() WHERE id = %s",
            (title, session_id)
        )
        conn.commit()
        return {"message": "会话标题更新成功"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()
@app.post("/register")
async def register_user(user: UserCreate):
    if user.password!=user.confirmpassword:
        return;
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 检查用户是否已存在
        cursor.execute("SELECT id FROM users WHERE username = %s", (user.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="用户名已存在")

        # 获取默认用户角色ID（假设普通用户角色ID为2）
        cursor.execute("SELECT id FROM roles WHERE name = 'user'")
        role = cursor.fetchone()
        if not role:
            raise HTTPException(status_code=500, detail="角色配置错误")

        # 创建新用户
        password_hash = get_password_hash(user.password)
        cursor.execute(
            """INSERT INTO users (username, password_hash, role_id, created_at) 
               VALUES (%s, %s, %s, NOW())""",
            (user.username, password_hash, role['id'])
        )
        conn.commit()
        return {"message": "注册成功"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()


# 添加忘记密码接口
@app.post("/forgot-password")
async def forgot_password(reset: PasswordReset):
    if reset.new_password!=reset.confirm_new_password:
        return;
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # 检查用户是否存在
        cursor.execute("SELECT id FROM users WHERE username = %s", (reset.username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="用户不存在")

        # 更新密码
        new_password_hash = get_password_hash(reset.new_password)
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (new_password_hash, user['id'])
        )
        conn.commit()
        return {"message": "密码重置成功"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.post("/users/me/password")
async def update_user_password(
        request: PasswordUpdateRequest,
        current_user: User = Depends(get_current_user)
):
    old_password = request.old_password  # 从模型取字段
    new_password = request.new_password
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 验证原密码
        cursor.execute("SELECT password_hash FROM users WHERE id = %s", (current_user.id,))
        user = cursor.fetchone()

        if not verify_password(old_password, user['password_hash']):
            print("8910")
            raise HTTPException(status_code=400, detail="原密码错误")


        # 更新密码
        new_password_hash = get_password_hash(new_password)
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (new_password_hash, current_user.id)
        )
        conn.commit()
        return {"message": "密码更新成功"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()


# 添加删除会话路由
@app.delete("/chat/sessions/{session_id}")
async def delete_chat_session(session_id: int, current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 验证会话属于当前用户
        cursor.execute(
            "SELECT user_id FROM chat_sessions WHERE id = %s",
            (session_id,)
        )
        session = cursor.fetchone()
        if not session or session[0] != current_user.id:
            raise HTTPException(status_code=403, detail="无权删除此会话")

        # 删除会话及关联消息
        cursor.execute("DELETE FROM chat_messages WHERE session_id = %s", (session_id,))
        cursor.execute("DELETE FROM chat_sessions WHERE id = %s", (session_id,))

        conn.commit()
        return {"message": "会话删除成功"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()


# 3. 增强上传接口的错误处理
@app.post("/users/me/avatar")
async def upload_user_avatar(
        file: UploadFile = File(...),
        current_user: User = Depends(get_current_user)
):
    try:
        # 允许的图片类型
        ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

        # 检查文件扩展名
        def allowed_file(filename):
            return '.' in filename and \
                filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

        if not allowed_file(file.filename):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="不支持的文件类型，仅允许 png, jpg, jpeg, gif"
            )

        # 读取文件内容并检查大小
        file_content = await file.read()
        if len(file_content) > 5 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="文件大小不能超过 5MB"
            )

        # 生成唯一文件名
        file_ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"avatar_{current_user.id}_{uuid.uuid4()}.{file_ext}"
        file_path = os.path.join(AVATAR_DIR, filename)

        # 保存文件
        try:
            with open(file_path, "wb") as buffer:
                buffer.write(file_content)
        except IOError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"文件保存失败: {str(e)}"
            )

        # 更新数据库
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            avatar_url = f"/static/avatars/{filename}"
            cursor.execute(
                "UPDATE users SET avatar = %s, updated_at = NOW() WHERE id = %s",
                (avatar_url, current_user.id)
            )
            conn.commit()
            return {"avatar_url": avatar_url}  # 确保返回蛇形命名字段
        except Error as e:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"数据库更新失败: {str(e)}"
            )
        finally:
            cursor.close()
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"上传处理失败: {str(e)}"
        )
    finally:
        await file.close()

@app.get("/users/my/avatar")
async def get_user_avatar(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT avatar FROM users WHERE id = %s",
            (current_user.id,)
        )
        result = cursor.fetchone()
        # 提供默认头像（需在 static/avatars 目录放置 default.png）
        default_avatar = "/static/avatars/default.png"
        return {"avatar_url": result["avatar"] if result and result["avatar"] else default_avatar}
    except Error as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()


# 在 FastAPI 路由中添加
@app.get("/dashboard/stats")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    """提供仪表盘统计数据（加密/解密次数）"""
    print(123456789)
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    print("当前用户的id:",current_user.id)
    # 假设从操作记录表统计（需根据实际数据库结构调整）
    cursor.execute("""
        SELECT 
            SUM(CASE WHEN action = 'encrypt' THEN 1 ELSE 0 END) AS encrypt_count,
            SUM(CASE WHEN action = 'decrypt' THEN 1 ELSE 0 END) AS decrypt_count
        FROM operation_logs
        WHERE user_id = %s
    """, (current_user.id,))

    stats = cursor.fetchone()
    print("stats为：",stats)
    return {
        "encrypt_count": stats["encrypt_count"],
        "decrypt_count": stats["decrypt_count"]
    }
    cursor.close()
    conn.close()
# 添加用户资料更新接口（保存姓名和邮箱）
@app.put("/users/me")
async def update_user_profile(
        profile: dict,  # 接收姓名和邮箱数据
        current_user: User = Depends(get_current_user)
):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 提取需要更新的字段
        name = profile.get("name")
        email = profile.get("email")

        # 验证邮箱格式（如果提供了邮箱）
        if email:
            import re
            if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
                raise HTTPException(status_code=400, detail="邮箱格式不正确")

        # 执行更新
        cursor.execute(
            "UPDATE users SET name = %s, email = %s, updated_at = NOW() WHERE id = %s",
            (name, email, current_user.id)
        )
        conn.commit()
        return {"message": "个人资料更新成功"}

    except Error as e:
        conn.rollback()
        if "Duplicate entry" in str(e) and "uk_email" in str(e):
            raise HTTPException(status_code=400, detail="该邮箱已被注册")
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        cursor.close()
        conn.close()
#挂载静态文件（只保留一个挂载语句）
app.mount("/static", StaticFiles(directory="static", html=True), name="static")