/**
 * 共享认证模块 - 所有页面引用
 * 功能：JWT token 管理、30分钟无操作自动登出、活动时间追踪
 */
const Auth = (function(){
  const TOKEN_KEY = 'spray_token';
  const USER_KEY = 'spray_user';
  const LAST_ACTIVE_KEY = 'spray_last_active';
  const TIMEOUT_MINUTES = 30; // 30分钟无操作自动登出

  function getToken(){ return localStorage.getItem(TOKEN_KEY); }
  function getUser(){ try{ return JSON.parse(localStorage.getItem(USER_KEY)||'null'); }catch(e){ return null; } }
  function getLastActive(){ return parseInt(localStorage.getItem(LAST_ACTIVE_KEY)||'0'); }

  function setAuth(token, user){
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    updateActive();
  }

  function clearAuth(){
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem(LAST_ACTIVE_KEY);
  }

  function updateActive(){
    localStorage.setItem(LAST_ACTIVE_KEY, String(Date.now()));
  }

  function isExpired(){
    const last = getLastActive();
    if(!last) return true;
    const elapsed = Date.now() - last;
    return elapsed > TIMEOUT_MINUTES * 60 * 1000;
  }

  function requireAuth(){
    const token = getToken();
    if(!token || isExpired()){
      clearAuth();
      location.href = '/login';
      return false;
    }
    return true;
  }

  // 带认证的 fetch 封装：自动加 token、更新活动时间、401自动登出
  async function fetchAuth(url, opts={}){
    if(!requireAuth()) throw new Error('未登录');
    updateActive();
    const headers = {...(opts.headers||{})};
    if(!headers['Authorization']){
      headers['Authorization'] = 'Bearer ' + getToken();
    }
    const res = await fetch(url, {...opts, headers});
    if(res.status === 401){
      clearAuth();
      location.href = '/login';
      throw new Error('登录已过期，请重新登录');
    }
    return res;
  }

  // 活动监听：鼠标、键盘、触摸、滚动都算活动
  function startActivityMonitor(){
    const events = ['mousedown','keydown','touchstart','scroll','click'];
    events.forEach(ev => document.addEventListener(ev, ()=>{
      if(getToken()) updateActive();
    }, {passive:true}));

    // 页面从后台切回前台时检查是否超时
    document.addEventListener('visibilitychange', ()=>{
      if(!document.hidden && getToken() && isExpired()){
        clearAuth();
        alert('由于长时间未操作，已自动登出，请重新登录');
        location.href = '/login';
      }
    });
  }

  // 启动定时检查（每分钟检查一次）
  function startExpiryCheck(){
    setInterval(()=>{
      if(getToken() && isExpired()){
        clearAuth();
        alert('由于长时间未操作，已自动登出，请重新登录');
        location.href = '/login';
      }
    }, 60 * 1000);
  }

  function init(){
    startActivityMonitor();
    startExpiryCheck();
  }

  return {
    getToken, getUser, getLastActive, setAuth, clearAuth,
    updateActive, isExpired, requireAuth, fetchAuth, init,
    TIMEOUT_MINUTES
  };
})();

// 页面加载时自动初始化活动监听
if(typeof document !== 'undefined'){
  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', ()=>Auth.init());
  }else{
    Auth.init();
  }
}
