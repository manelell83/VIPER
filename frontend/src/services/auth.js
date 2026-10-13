// Stores the JWT for the current browser tab.
//
// sessionStorage is cleared when the tab is closed. Like any storage readable
// from JavaScript it would be exposed by an XSS bug; an httpOnly cookie would
// avoid that but would require CSRF protection, so we keep a bearer token.
const TOKEN_KEY = "viper_token";
const USER_KEY = "viper_user";

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function getUser() {
  try {
    return JSON.parse(sessionStorage.getItem(USER_KEY));
  } catch {
    return null;
  }
}

export function saveSession(token, user) {
  sessionStorage.setItem(TOKEN_KEY, token);
  sessionStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USER_KEY);
}
