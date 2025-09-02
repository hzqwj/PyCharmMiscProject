

// 在文件顶部添加以下组件定义
const Dashboard = {
  setup() {
    // 从根组件注入状态
    const currentUser = inject('currentUser');
    const lastLoginTime = inject('lastLoginTime');
    const encryptCount = inject('encryptCount');
    const decryptCount = inject('decryptCount');
    console.log("Dashboard注入的值:", {
      currentUser,
      lastLoginTime,
      encryptCount,
      decryptCount
    });
    return {
      currentUser,
      lastLoginTime,
      encryptCount,
      decryptCount
    };
  },
  template: '#dashboard-template'
};
const Permissions = {
  setup() {
    // 从根组件注入所需方法和数据
    const hasPermission = inject('hasPermission', () => false);
    const permissionForm = inject('permissionForm', {
      username: '',
      resource: '',
      action: 'read'
    });
    const assignPermission = inject('assignPermission', () => {});

    return {
      hasPermission,
      permissionForm,
      assignPermission
    };
  },
  template: '#permissions-template'
};
// 在Encrypt组件的setup函数中添加解密功能
const Encrypt = {
  setup() {
    const { nextTick } = Vue;

    // 确保注入的对象是响应式的
    const encryptForm = inject('encryptForm');
    const decryptForm = inject('decryptForm');
    const encryptData = inject('encryptData', () => {});
    const decryptData = inject('decryptData', () => {});

    onMounted(() => {
      nextTick(() => {
        if (encryptForm) {
          encryptForm.plainText = '这是测试内容';
          console.log("plainText", encryptForm.plainText);
        }
      });
    });

    // 添加复制功能
    const copyEncryptedText = () => {
      if (!encryptForm.encryptedText) {
        ElMessage.warning('没有内容可复制');
        return;
      }

      navigator.clipboard.writeText(encryptForm.encryptedText)
        .then(() => {
          ElMessage.success('已复制到剪贴板');
        })
        .catch(err => {
          console.error('复制失败:', err);
          ElMessage.error('复制失败');
        });
    };

    // 添加解密文本复制功能
    const copyDecryptedText = () => {
      if (!decryptForm.decryptedText) {
        ElMessage.warning('没有内容可复制');
        return;
      }

      navigator.clipboard.writeText(decryptForm.decryptedText)
        .then(() => {
          ElMessage.success('已复制到剪贴板');
        })
        .catch(err => {
          console.error('复制失败:', err);
          ElMessage.error('复制失败');
        });
    };

    // 清空功能
    const clearForm = () => {
      encryptForm.plainText = '';
      encryptForm.encryptedText = '';
    };

    return {
      encryptForm,
      decryptForm,
      encryptData,
      decryptData,
      copyEncryptedText,
      copyDecryptedText,
      clearForm
    };
  },
  template: '#encrypt-template'
};

const Decrypt = {
  setup() {
    // 从根组件注入所需方法和数据，添加默认值防止undefined
    const decryptForm = inject('decryptForm', {
      encryptedText: '',
      decryptedText: ''
    });
    const decryptData = inject('decryptData', () => {});

    return {
      decryptForm,
      decryptData
    };
  },
  template: '#decrypt-template'
};
// 在Decrypt组件定义后添加ChatComponent
const ChatComponent = {
  setup() {
    const { nextTick } = Vue;

    // 从根组件注入所需状态和方法
    const currentUser = inject('currentUser');
    const chatSessions = inject('chatSessions');
    const currentSessionId = inject('currentSessionId');
    const messages = inject('messages');
    const newMessage = inject('newMessage');
    const isSending = inject('isSending');
    const showChatSidebar = inject('showChatSidebar');
    const sessionTitles = inject('sessionTitles');
    const loadingMore = inject('loadingMore');
    const hasMoreMessages = inject('hasMoreMessages');
    const currentMessagePage = inject('currentMessagePage');

    // 注入方法
    const loadChatSessions = inject('loadChatSessions');
    const createNewSession = inject('createNewSession');
    const loadMessages = inject('loadMessages');
    const deleteSession = inject('deleteSession');
    const sendMessage = inject('sendMessage');
    const editSessionTitle = inject('editSessionTitle');
    const toggleChatSidebar = inject('toggleChatSidebar');
    const scrollToBottom = inject('scrollToBottom');

    // 本地方法
    const loadMoreMessages = () => {
      if (currentSessionId.value && hasMoreMessages.value && !loadingMore.value) {
        loadMessages(currentSessionId.value, true);
      }
    };

    // 组件挂载时加载会话
    onMounted(() => {
      loadChatSessions();
    });

    return {
      currentUser,
      chatSessions,
      currentSessionId,
      messages,
      newMessage,
      isSending,
      showChatSidebar,
      sessionTitles,
      loadingMore,
      hasMoreMessages,
      loadChatSessions,
      createNewSession,
      loadMessages,
      deleteSession,
      sendMessage,
      editSessionTitle,
      toggleChatSidebar,
      scrollToBottom,
      loadMoreMessages
    };
  },
  template: '#chat-template'
};
const { createApp, ref, reactive, onMounted, toRefs, getCurrentInstance,provide,inject} = Vue;
const { ElMessage, ElLoading, ElMessageBox } = ElementPlus;
const routes = [
  { path: '/', redirect: '/dashboard' ,meta:{menu:'dashboard'}},
  { path: '/dashboard', component: Dashboard, meta: { menu: 'dashboard' } },
  { path: '/encrypt', component: Encrypt, meta: { menu: 'encrypt' } },
  { path: '/decrypt', component: Decrypt, meta: { menu: 'decrypt' } },
  { path: '/permissions', component: Permissions, meta: { menu: 'permissions' } },
  { path: '/chat', component: ChatComponent, meta: { menu: 'chat' } } // 使用新的组件
];

const router = VueRouter.createRouter({
  history: VueRouter.createWebHashHistory(),
  routes
});
router.beforeEach((to, from) => {
  console.log(`路由从 ${from.path} 到 ${to.path}`);
});
const app = createApp({
   setup() {
    const encryptCount = ref(0);
    const decryptCount = ref(0);
    const lastLoginTime = ref('');
    const menuItems = ref([]);
    const isAuthenticated = ref(false);
    const currentUser = reactive({ username: '', role: '', name: '', email: '', avatar: '/static/ai-avatar.png' }); // 设置默认头像为ai-avatar.png
    const loadingMore = ref(false);
    const activeMenu = ref('dashboard');
    const loginForm = reactive({ username: '', password: '' });
    const permissions = ref([]);
    const showUserProfile = ref(false);
    const showSystemSettings = ref(false);
    const chatSessions = ref([]);
    const currentSessionId = ref(null);
    const messages = ref([]);
    const newMessage = ref('');
    const isSending = ref(false);
    const sessionTitles = ref({});
    const showChatSidebar = ref(true);
    const { proxy } = getCurrentInstance();
    const currentMessagePage = ref(1);
    const hasMoreMessages = ref(true);
    const userProfileForm = reactive({
        username: '',
        oldPassword: '',
        newPassword: '',
        confirmPassword: '',
        name: '',
        email: '',
        avatar: null,
        avatarUrl: '/static/ai-avatar.png' // 设置默认头像为ai-avatar.png
    });
    const systemSettingsForm = reactive({
        theme: 'light',
        notification: true,
        language: 'zh-CN',
        defaultPage: 'dashboard',
        autoLogin: false
    });
    const profileRules = reactive({
        oldPassword: [
            { required: true, message: '请输入原密码', trigger: 'blur' }
        ],
        newPassword: [
            { required: true, message: '请输入新密码', trigger: 'blur' },
            { min: 6, message: '密码长度不能少于6位', trigger: 'blur' }
        ],
        name: [
            { required: true, message: '请输入姓名', trigger: 'blur' },
            { min: 2, max: 20, message: '姓名长度在2-20之间', trigger: 'blur' }
        ],
        email: [
            { required: true, message: '请输入邮箱', trigger: 'blur' },
            { type: 'email', message: '请输入正确的邮箱格式', trigger: 'blur' }
        ]
    });
    //加载菜单函数
    const loadMenuItems = async () => {
  try {
    const response = await axios.get('/menu-items', {
      headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
    });
    menuItems.value = response.data;
  } catch (error) {
    console.error('加载菜单失败:', error);
  }
};
    // app.js 中完善 loadUserProfileData 函数，确保数据正确绑定
const loadUserProfileData = async () => {
  try {
    const response = await axios.get('/users/me', {
      headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
    });
    const userData = response.data;
    // 确保所有用户信息字段正确赋值（补充可能缺失的字段）
    currentUser.name = userData.name || currentUser.username; // 若name为空，用username兜底
    currentUser.email = userData.email || '未设置邮箱';
    currentUser.avatar = (userData.avatar || '/static/avatars/default-avatar.png').trim();
    currentUser.role = userData.role || currentUser.role; // 补充角色信息

    userProfileForm.avatarUrl = currentUser.avatar.trim();
    fetchLastLogin(); // 确保最后登录时间被调用
    console.log('用户数据加载成功：', currentUser);
    proxy.$forceUpdate();
  } catch (error) {
    console.error('加载用户资料失败:', error);
    // 失败时手动设置默认值，避免界面空白
    currentUser.avatar = '/static/ai-avatar.png'; // 设置默认头像
    userProfileForm.avatarUrl = '/static/ai-avatar.png'; // 设置默认头像
  }
};
    // 登录表单验证规则
    const loginRules = reactive({
      username: [
        { required: true, message: '请输入用户名', trigger: 'blur' }
      ],
      password: [
        { required: true, message: '请输入密码', trigger: 'blur' }
      ]
    });
// 修改 loadDashboardStats 函数
const loadDashboardStats = async () => {
  try {
    const response = await axios.get('/dashboard/stats', {
      headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
    });

    // 确保处理蛇形命名
    encryptCount.value = response.data.encrypt_count || 0;
    decryptCount.value = response.data.decrypt_count || 0;

    console.log('统计数据加载成功', encryptCount.value, decryptCount.value);
    await loadUserProfileData();
    console.log('用户数据加载后:', currentUser);
    await fetchLastLogin();
    console.log('最后登录时间:', lastLoginTime.value);
  } catch (error) {
    console.error('加载统计失败:', error);
    ElMessage.error('加载统计失败，请稍后重试');
    // 设置默认值
    encryptCount.value = 0;
    decryptCount.value = 0;
  }
};
    // 加密数据表单
    const encryptForm = reactive({ plainText: '', encryptedText: '' });

    // 解密数据表单
    const decryptForm = reactive({
      encryptedText: '',
      decryptedText: ''
    });

    // 权限分配表单
    const permissionForm = reactive({
      username: '',
      resource: '',
      action: 'read'
    });

    // 检查权限
    const hasPermission = (resource, action) => {
      if (currentUser.role === 'admin') return true;
      return permissions.value.some(p =>
        p.resource === resource && p.action === action
      );
    };

    // 登录
    const handleLogin = async () => {
      try {
        const response = await axios.post('/token',
          `username=${loginForm.username}&password=${loginForm.password}`,
          {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          }
        );

        localStorage.setItem('access_token', response.data.access_token);

        // 解析JWT获取用户信息
        const tokenData = JSON.parse(atob(response.data.access_token.split('.')[1]));
        currentUser.username = tokenData.sub;
        currentUser.role = tokenData.role;
        isAuthenticated.value = true;
        console.log('登录成功，认证状态:', isAuthenticated.value);
        // 获取用户权限
        await fetchPermissions();
        // 加载用户设置
        await loadUserSettings();
        // 加载用户资料
        await loadUserProfileData();
        // 跳转到默认页面或仪表盘
        router.push(systemSettingsForm.defaultPage || '/dashboard');

      } catch (error) {
        ElMessage.error('登录失败: ' + (error.response?.data?.detail || '用户名或密码错误'));
      }
    };

    // 获取用户权限
    const fetchPermissions = async () => {
      try {
        const response = await axios.get('/permissions', {
          params: { username: currentUser.username },
          headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
        });
        permissions.value = response.data;
      } catch (error) {
        console.error('获取权限失败:', error);
      }
    };
    // 退出登录 - 修复版本
    const handleLogout = () => {
      console.log('触发退出登录处理');
      // 确保ElMessageBox可用
      if (!ElMessageBox) {
        console.error('ElMessageBox未加载');
        // 即使没有弹窗，也执行退出操作
        performLogout();
        return;
      }

      ElMessageBox.confirm(
        '确定要退出登录吗？',
        '确认退出',
        {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        }
      ).then(() => {
        performLogout();
         ElMessageBox.close();
      }).catch(() => {
        // 用户取消操作
        ElMessage.info('已取消退出');
         ElMessageBox.close();
      });
    };
    // 新增获取最后登录时间的方法
const fetchLastLogin = async () => {
  try {
    const response = await axios.get('/users/me/last-login', {
      headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
    });
    lastLoginTime.value = new Date(response.data.last_login).toLocaleString();
  } catch (error) {
    console.error('获取最后登录时间失败:', error);
  }
};
    // 实际执行退出登录的函数
    const performLogout = () => {
      try {
        console.log('执行实际退出登录操作');
        // 清除本地存储
        if (!systemSettingsForm.autoLogin) {
          localStorage.removeItem('access_token');
        }
        localStorage.removeItem('user_settings');

        // 重置用户状态
        isAuthenticated.value = false;
        currentUser.username = '';
        currentUser.role = '';
        currentUser.name = '';
        currentUser.email = '';
        currentUser.avatar = '/static/ai-avatar.png'; // 重置为默认头像
        permissions.value = [];

        // 跳转到登录页
        router.push('/');

        // 显示成功消息
        ElMessage.success('退出登录成功');
      } catch (error) {
        console.error('退出登录过程出错:', error);
        ElMessage.error('退出登录失败，请重试');
      }
    };

// 在app.js中修改encryptData函数
const encryptData = async () => {
  if (!encryptForm.plainText) {
    ElMessage.warning('请输入要加密的文本');
    return;
  }

  try {
    const response = await axios.post('/encrypt',
      { data: encryptForm.plainText },
      {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data && response.data.encrypted_data) {
      encryptForm.encryptedText = response.data.encrypted_data;
      ElMessage.success('加密成功');
    } else {
      throw new Error('服务器返回的数据格式不正确');
    }
  } catch (error) {
    console.error('加密错误详情:', error);
    const errorMsg = error.response?.data?.detail ||
                     error.response?.data?.message ||
                     error.message ||
                     '服务器错误';
    ElMessage.error('加密失败: ' + errorMsg);
  }
};

    // 解密数据
    const decryptData = async () => {
      if (!decryptForm.encryptedText) {
        ElMessage.warning('请输入要解密的文本');
        return;
      }

      try {
        const response = await axios.post('/decrypt',
          { data: decryptForm.encryptedText },
          { headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` } }
        );
        decryptForm.decryptedText = response.data.decrypted_data;
      } catch (error) {
        ElMessage.error('解密失败: ' + (error.response?.data?.detail || '无效的加密文本'));
      }
    };

    // 注册表单
    const showRegister = ref(false);
    const registerForm = reactive({
      username: '',
      password: '',
      confirmPassword: ''
    });
    const registerRules = reactive({
      username: [
        { required: true, message: '请输入用户名', trigger: 'blur' }
      ],
      password: [
        { required: true, message: '请输入密码', trigger: 'blur' },
        { min: 6, message: '密码长度不能少于6位', trigger: 'blur' }
      ],
      confirmPassword: [
        { required: true, message: '请确认密码', trigger: 'blur' },
        {
          validator: (rule, value, callback) => {
            if (value !== registerForm.password) {
              callback(new Error('两次输入的密码不一致'));
            } else {
              callback();
            }
          },
          trigger: 'blur'
        }
      ]
    });

    // 忘记密码表单
    const showForgotPassword = ref(false);
    const forgotForm = reactive({
      username: '',
      newPassword: '',
      confirmNewPassword: ''
    });
    const forgotRules = reactive({
      username: [
        { required: true, message: '请输入用户名', trigger: 'blur' }
      ],
      newPassword: [
        { required: true, message: '请输入新密码', trigger: 'blur' },
        { min: 6, message: '密码长度不能少于6位', trigger: 'blur' }
      ],
      confirmNewPassword: [
        { required: true, message: '请确认新密码', trigger: 'blur' },
        {
          validator: (rule, value, callback) => {
            if (value !== forgotForm.newPassword) {
              callback(new Error('两次输入的密码不一致'));
            } else {
              callback();
            }
          },
          trigger: 'blur'
        }
      ]
    });

    // 处理注册
    const handleRegister = async () => {
      try {
        const response = await axios.post('/register', {
          username: registerForm.username,
          password: registerForm.password,
          confirmpassword:registerForm.confirmPassword
        });
        if(registerForm.password!==registerForm.confirmPassword){
    ElMessage.error('两次输入的密码不一致');
    return;
  }
        ElMessage.success('注册成功，请登录');
        showRegister.value = false;
        registerForm.username = '';
        registerForm.password = '';
        registerForm.confirmPassword = '';
      } catch (error) {
        ElMessage.error('注册失败: ' + (error.response?.data?.detail || '用户名已存在'));
      }
    };

    // 处理忘记密码
    const handleForgotPassword = async () => {
      try {
        const response = await axios.post('/forgot-password', {
          username: forgotForm.username,
          new_password: forgotForm.newPassword,
          confirm_new_password:forgotForm.confirmNewPassword
        });
        if (forgotForm.newPassword !== forgotForm.confirmNewPassword) {
    ElMessage.error('两次输入的密码不一致');
    return;
  }
        ElMessage.success('密码重置成功，请登录！');
        showForgotPassword.value = false;
        forgotForm.username = '';
        forgotForm.newPassword = '';
        forgotForm.confirmNewPassword = '';
      } catch (error) {
        ElMessage.error('密码重置失败: ' + (error.response?.data?.detail || '用户不存在'));
      }
    };

    // 分配权限
    const assignPermission = async () => {
     if (!permissionForm.username || !permissionForm.resource || !permissionForm.action) {
  ElMessage.warning('请填写完整的权限信息（用户名、资源、操作）');
  return;
}
      try {
       axios.post( '/permissions',  // URL
  {
    // 请求体（body）：只放 resource 和 action 顶级字段
    resource: permissionForm.resource,
    action: permissionForm.action
  },
  {
    // 查询参数（query）：放 username
    params: {
      username: permissionForm.username
    },
    headers: {
      Authorization: `Bearer ${localStorage.getItem('access_token')}`
    }
  }
);
        ElMessage.success('权限分配成功');
        permissionForm.username = '';
        permissionForm.resource = '';
        permissionForm.action = 'read';
      } catch (error) {
        ElMessage.error('权限分配失败: ' + (error.response?.data?.detail || '服务器错误'));
      }
    };

    // 个人中心 - 加载用户信息
    const loadUserProfile = () => {
        userProfileForm.username = currentUser.username;
        userProfileForm.name = currentUser.name;
        userProfileForm.email = currentUser.email;
        userProfileForm.avatarUrl = currentUser.avatar || '/static/ai-avatar.png'; // 使用默认头像
        userProfileForm.oldPassword = '';
        userProfileForm.newPassword = '';
        userProfileForm.confirmPassword = '';
        showUserProfile.value = true;
    };

    // 1. 修复上传字段名和文件对象获取
const handleAvatarUpload = async (file) => {
    // 检查文件类型
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.raw.type)) {
        ElMessage.error('仅支持 JPG、PNG、GIF 格式的图片');
        return;
    }

    // 检查文件大小 (5MB)
    if (file.raw.size > 5 * 1024 * 1024) {
        ElMessage.error('文件大小不能超过 5MB');
        return;
    }

    const formData = new FormData();
    formData.append('file', file.raw);  // 关键修复：字段名必须为'file'

    try {
        const loading = ElLoading.service({
            lock: true,
            text: '上传中...',
            background: 'rgba(0, 0, 0, 0.7)'
        });

        const response = await axios.post('/users/me/avatar', formData, {
            headers: {
                Authorization: `Bearer ${localStorage.getItem('access_token')}`
            }
        });
        let avatarUrl = response.data.avatar_url.trim(); // 新增：去除前后空格
        loading.close();

        if (!avatarUrl.startsWith('/static')) {
            avatarUrl = '/static/avatars/' + avatarUrl.trim();
        }

        userProfileForm.avatarUrl = avatarUrl;
        currentUser.avatar = avatarUrl;

        ElMessage.success('头像上传成功');
    } catch (error) {
        console.error('上传错误详情:', error);
        const errorMsg = error.response?.data?.detail ||
                         error.message ||
                         '服务器错误，请稍后重试';
        ElMessage.error(`头像上传失败: ${errorMsg}`);
    }
};
// 2. 为上传组件添加前置校验（在Vue组件的methods中）
const beforeAvatarUpload = (file) => {
    const isImage = file.type.startsWith('image/');
    if (!isImage) {
        ElMessage.error('请上传图片文件!');
        return false;
    }

    const isLt5M = file.size / 1024 / 1024 < 5;
    if (!isLt5M) {
        ElMessage.error('头像大小不能超过5MB!');
        return false;
    }
    return true;
};
// 保存个人资料 - 添加添加表单验证
const saveUserProfile = async () => {
    // 姓名验证
    if (!userProfileForm.name.trim()) {
        ElMessage.error('请输入姓名');
        return;
    }
    if (userProfileForm.name.length < 2 || userProfileForm.name.length > 20) {
        ElMessage.error('姓名长度必须在2-20个字符之间');
        return;
    }

    // 邮箱验证
    if (!userProfileForm.email.trim()) {
        ElMessage.error('请输入邮箱');
        return;
    }
    const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailReg.test(userProfileForm.email)) {
        ElMessage.error('请输入正确的邮箱格式');
        return;
    }

    try {
        await axios.put('/users/me', {
            name: userProfileForm.name,
            email: userProfileForm.email
        }, {
            headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
        });
        currentUser.name = userProfileForm.name;
        currentUser.email = userProfileForm.email;
        ElMessage.success('个人资料保存成功');

    } catch (error) {
        ElMessage.error('保存失败: ' + (error.response?.data?.detail || '服务器错误'));
    }
};
    // 个人中心 - 修改密码
    const updatePassword = async () => {
        try {
            const response = await axios.post('/users/me/password', {
                old_password: userProfileForm.oldPassword,
                new_password: userProfileForm.newPassword
            }, {
                headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
            });

            ElMessage.success('密码修改成功，请重新登录');
            showUserProfile.value = false;
            handleLogout();
        } catch (error) {
            ElMessage.error('密码修改失败: ' + (error.response?.data?.detail || '原密码错误'));
        }
    };

    // 系统设置 - 加载设置
    const loadUserSettings = () => {
        const savedSettings = localStorage.getItem('user_settings');
        if (savedSettings) {
            Object.assign(systemSettingsForm, JSON.parse(savedSettings));
        }
        // 应用保存的主题
        if (systemSettingsForm.theme === 'dark') {
            document.documentElement.classList.add('dark-theme');
        } else {
            document.documentElement.classList.remove('dark-theme');
        }
    };

    // 清除缓存
    const clearCache = () => {
        ElMessageBox.confirm(
            '确定要清除所有缓存数据吗？这不会影响您的账户信息',
            '确认清除',
            {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }
        ).then(() => {
            localStorage.removeItem('user_settings');
            sessionStorage.clear();
            ElMessage.success('缓存已清除，将重新加载页面');
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        }).catch(() => {
            ElMessage.info('已取消清除缓存');
        });
    };

    // 系统设置 - 保存设置
    const saveSystemSettings = () => {
        localStorage.setItem('user_settings', JSON.stringify(systemSettingsForm));
        ElMessage.success('设置保存成功');

        // 应用主题设置
        if (systemSettingsForm.theme === 'dark') {
            document.documentElement.classList.add('dark-theme');
        } else {
            document.documentElement.classList.remove('dark-theme');
        }

        showSystemSettings.value = false;
    };

    // 处理个人中心和设置命令
    const handleCommand = (command) => {
        console.log('接收到命令:', command);
        if (command === 'profile') {
            loadUserProfile();
        } else if (command === 'settings') {
            showSystemSettings.value = true;
        } else if (command === 'logout') {
            handleLogout();
        }
    };
    const loadChatSessions = async () => {
      try {
        const response = await axios.get('/chat/sessions', {
          headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
        });
        chatSessions.value = response.data;
        // 缓存会话标题
        response.data.forEach(session => {
          sessionTitles.value[session.id] = session.title;
        });
         if (chatSessions.value.length > 0 && !currentSessionId.value) {
      currentSessionId.value = chatSessions.value[0].id;
      loadMessages(currentSessionId.value);
    }
      } catch (error) {
        console.error('加载会话失败:', error);
        ElMessage.error('加载会话失败，请刷新页面重试');
      }
    };

// 修改 app.js 中的 createNewSession 函数，支持自定义会话标题
const createNewSession = async () => {
  try {
    const response = await axios.post(`/chat/sessions?title=${encodeURIComponent('新对话')}`,
      {}, // 空请求体
      { headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` } }
    );

    currentSessionId.value = response.data.session_id;
    messages.value = [];

    // 重新加载会话列表
    await loadChatSessions();

    ElMessage.success('新对话已创建');
  } catch (error) {
    ElMessage.error('创建会话失败: ' + (error.response?.data?.detail || '服务器错误'));
  }
};

// 修改loadMessages函数，添加加载更多功能
const loadMessages = async (sessionId, loadMore = false) => {
  if (!sessionId) return;

  if (loadMore) {
    loadingMore.value = true;
    currentMessagePage.value++;
  } else {
    currentMessagePage.value = 1;
    messages.value = [];
  }

  try {
    const response = await axios.get(`/chat/sessions/${sessionId}/messages`, {
      params: { page: currentMessagePage.value, page_size: 20 },
      headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
    });

    const messagesData = Array.isArray(response.data) ? response.data : [];

    if (loadMore) {
      // 将新加载的消息添加到开头
      messages.value = [...messagesData.reverse(), ...messages.value];
    } else {
      messages.value = messagesData.reverse();
    }
    hasMoreMessages.value = messagesData.length === 20;
    if (!loadMore) {
      // 只有首次加载时才滚动到底部
      nextTick(() => {
        scrollToBottom();
      });
    }
  } catch (error) {

  } finally {
    loadingMore.value = false;
  }
};

    const deleteSession = async (sessionId) => {
      try {
        await axios.delete(`/chat/sessions/${sessionId}`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
        });
        if (currentSessionId.value === sessionId) {
          currentSessionId.value = null;
          messages.value = [];
        }
        loadChatSessions();
        ElMessage.success('会话已删除');
      } catch (error) {
        ElMessage.error('删除失败: ' + (error.response?.data?.detail || '服务器错误'));
      }
    };

// 修改sendMessage方法，确保消息发送后正确滚动
const sendMessage = async () => {
  if (!newMessage.value.trim() || isSending.value) return;

  isSending.value = true;
  const messageContent = newMessage.value.trim();
  newMessage.value = '';

  // 添加用户消息到界面
  const userMessage = {
    id: Date.now(),
    role: 'user',
    content: messageContent,
    created_at: new Date().toISOString()
  };
  messages.value.push(userMessage);

  // 立即滚动到底部（用户消息）
  scrollToBottom();

  try {
    const response = await axios.post('/chat/messages', {
      message: messageContent,
      session_id: currentSessionId.value
    }, {
      headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
    });

    // 添加AI回复到界面
    const aiMessage = {
      id: response.data.ai_message_id || Date.now(),
      role: 'assistant',
      content: response.data.response,
      created_at: new Date().toISOString()
    };
    messages.value.push(aiMessage);

    const errorKeywords = ["抱歉", "失败", "错误", "不可用", "超时"];
    const isError = errorKeywords.some(keyword => aiMessage.content.includes(keyword));
    if (isError) {
        ElMessage.error({
            message: `AI服务提示：${aiMessage.content}`,
            duration: 6000,
            showClose: true
        });
    }

    if (!currentSessionId.value) {
      currentSessionId.value = response.data.session_id;
    }

    await loadChatSessions();
    // AI回复后再次滚动到底部
    scrollToBottom();
  } catch (error) {
    console.error('发送消息错误:', error);
    const errorMessage = {
      id: Date.now(),
      role: 'assistant',
      content: '消息发送失败，请重试',
      created_at: new Date().toISOString()
    };
    messages.value.push(errorMessage);
    ElMessage.error('发送失败: ' + (error.response?.data?.detail || '服务器错误'));
    scrollToBottom(); // 错误消息也需要滚动
  } finally {
    isSending.value = false;
  }
};


// 将editSessionTitle方法移出sendMessage方法
const editSessionTitle = async (sessionId) => {
  const title = prompt('请输入新的会话标题:', sessionTitles.value[sessionId]);
  if (!title || title.trim() === '') return;
  try {
    if (!sessionId) {
      await createNewSession(title.trim());
      return;
    }
    await axios.put(`/chat/sessions/${sessionId}`,
      { title: title.trim() },
      { headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` } }
    );
    sessionTitles.value[sessionId] = title.trim();
    loadChatSessions();
    ElMessage.success('标题更新成功');
  } catch (error) {
    ElMessage.error('更新失败: ' + (error.response?.data?.detail || '服务器错误'));
  }
};
// 修改scrollToBottom方法，确保正确滚动
// 修改 scrollToBottom 方法，确保正确引入 nextTick
const scrollToBottom = () => {
  // 使用 Vue.nextTick 确保 DOM 已更新
  Vue.nextTick(() => {
    const chatContainer = document.getElementById('chat-messages-container');
    if (chatContainer) {
      // 强制重绘
      chatContainer.scrollTop = chatContainer.scrollHeight;
      // 双重确保滚动到底部
      setTimeout(() => {
        chatContainer.scrollTop = chatContainer.scrollHeight;
      }, 0);
    }
  });
};
    // 在scrollToBottom方法后添加
    const toggleChatSidebar = () => {
    showChatSidebar.value = !showChatSidebar.value;
    };

    // 初始化检查登录状态
    // 修改app.js中的onMounted部分
onMounted(() => {
  console.log("根组件挂载，当前用户:", currentUser);
  const token = localStorage.getItem('access_token');
  console.log('本地存储中的 token:', token);
  if (token) {
    try {
      const tokenData = JSON.parse(atob(token.split('.')[1]));
      currentUser.username = tokenData.sub;
      currentUser.role = tokenData.role;
      isAuthenticated.value = true;
      fetchPermissions();
      loadUserSettings();
      loadUserProfileData();
      // 移除了loadChatSessions()调用
      loadMenuItems();
      loadDashboardStats();
      fetchLastLogin();
      console.log('解析后的 token 数据:', tokenData);
    } catch (e) {
      localStorage.removeItem('access_token');
    }
  }
});
    provide('currentUser', currentUser); // 提供用户信息
    provide('lastLoginTime', lastLoginTime); // 提供最后登录时间
    provide('encryptCount', encryptCount); // 提供加密次数
    provide('decryptCount', decryptCount); // 提供解密次数
    provide('hasPermission', hasPermission);
    provide('permissionForm', permissionForm);
    provide('assignPermission', assignPermission);
    // 在provide部分添加
provide('encryptForm', encryptForm);
provide('decryptForm', decryptForm);
provide('encryptData', encryptData);
provide('decryptData', decryptData);
provide('chatSessions', chatSessions);
provide('currentSessionId', currentSessionId);
provide('messages', messages);
provide('newMessage', newMessage);
provide('isSending', isSending);
provide('showChatSidebar', showChatSidebar);
provide('sessionTitles', sessionTitles);
provide('loadingMore', loadingMore);
provide('hasMoreMessages', hasMoreMessages);
provide('currentMessagePage', currentMessagePage);
provide('loadChatSessions', loadChatSessions);
provide('createNewSession', createNewSession);
provide('loadMessages', loadMessages);
provide('deleteSession', deleteSession);
provide('sendMessage', sendMessage);
provide('editSessionTitle', editSessionTitle);
provide('toggleChatSidebar', toggleChatSidebar);
provide('scrollToBottom', scrollToBottom);
    return {
      isAuthenticated,
      currentUser,
      activeMenu,
      loginForm,
      loginRules,
      encryptForm,
      decryptForm,
      permissionForm,
      hasPermission,
      handleLogin,
      handleLogout,
      encryptData,
      decryptData,
      assignPermission,
      showRegister,
      profileFormRef: ref(null),
      registerForm,
      registerRules,
      showForgotPassword,
      forgotForm,
      forgotRules,
      handleRegister,
      handleForgotPassword,
      showUserProfile,
      userProfileForm,
      profileRules,
      updatePassword,
      handleAvatarUpload,
      saveUserProfile,
      showSystemSettings,
      systemSettingsForm,
      saveSystemSettings,
      clearCache,
      handleCommand,
      chatSessions,
      currentSessionId,
      messages,
      newMessage,
      isSending,
      showChatSidebar,
      sessionTitles,
      loadChatSessions,
      createNewSession,
      loadMessages,
      deleteSession,
      sendMessage,
      scrollToBottom,
      menuItems,
      hasMoreMessages,
      lastLoginTime
    };
  }
});

app.use(ElementPlus);
app.use(router);
app.mount('#app');
console.log('Vue 应用已挂载');