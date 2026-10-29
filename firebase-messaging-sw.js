/* Firebase Cloud Messaging service worker — TEST PROJECT ONLY.
   Replace every REPLACE_WITH_* value with the matching Firebase web-app config.
   Do not add server credentials or private keys to this file. */
importScripts('https://www.gstatic.com/firebasejs/13.0.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/13.0.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyDPyoYHZk5bfoiepl4IRSBvOZ75Yvzu2yY",
  authDomain: "school-permissions-push-test.firebaseapp.com",
  projectId: "school-permissions-push-test",
  storageBucket: "school-permissions-push-test.firebasestorage.app",
  messagingSenderId: "181978320458",
  appId: "1:181978320458:web:86b855dabeaaf3f9a360b3"
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  const notification = payload.notification || {};
  const title = notification.title || 'نظام الاستئذانات — اختبار';
  const options = {
    body: notification.body || 'هذا إشعار تجريبي من Firebase.',
    icon: './icons/icon-192.png',
    data: { url: (payload.fcmOptions && payload.fcmOptions.link) || './' }
  };
  self.registration.showNotification(title, options);
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = event.notification.data && event.notification.data.url
    ? event.notification.data.url : './';
  event.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windows) => {
    for (const client of windows) {
      if ('focus' in client) {
        client.navigate(target);
        return client.focus();
      }
    }
    if (clients.openWindow) return clients.openWindow(target);
  }));
});
