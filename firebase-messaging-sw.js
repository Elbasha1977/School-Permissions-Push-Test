
/* Firebase Cloud Messaging Service Worker */

importScripts('https://www.gstatic.com/firebasejs/13.0.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/13.0.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyDPyoYHZk5bfoiepl4IRSBvOZ75Yvzu2Y",
  authDomain: "school-permissions-push-test.firebaseapp.com",
  projectId: "school-permissions-push-test",
  storageBucket: "school-permissions-push-test.firebasestorage.app",
  messagingSenderId: "181978320458",
  appId: "1:181978320458:web:86b855dabeaaf3f9a360b3"
});

const messaging = firebase.messaging();

const APP_URL =
  'https://elbasha1977.github.io/School-Permissions-Push-Test/';

messaging.onBackgroundMessage((payload) => {
  // Firebase displays notification payloads automatically.
  // Avoid showing the same notification twice.
  if (payload && payload.notification) return;

  const data = (payload && payload.data) || {};

  const title = data.title || 'نظام الاستئذان والإجازات';
  const body = data.body || data.message || 'لديك تحديث جديد في النظام.';
  const target = data.url || data.link || APP_URL;

  return self.registration.showNotification(title, {
    body: body,
    icon: './icon-192.png',
    badge: './icon-192.png',
    data: { url: target }
  });
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const rawTarget =
    event.notification.data && event.notification.data.url
      ? event.notification.data.url
      : APP_URL;

  let target = APP_URL;

  try {
    const parsed = new URL(rawTarget, APP_URL);

    if (
      parsed.origin === 'https://elbasha1977.github.io' &&
      parsed.pathname.startsWith('/School-Permissions-Push-Test/')
    ) {
      target = parsed.href;
    }
  } catch (_) {}

  event.waitUntil((async () => {
    const windows = await clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    });

    for (const client of windows) {
      if ('focus' in client) {
        if ('navigate' in client) await client.navigate(target);
        return client.focus();
      }
    }

    if (clients.openWindow) {
      return clients.openWindow(target);
    }
  })());
});
