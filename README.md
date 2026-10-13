# مشروع فحص ID

باك إند Python مع PostgreSQL على Render، وSQLite للتجربة المحلية.
الأرقام تخزن كنص للحفاظ على الأصفار مثل 00123. لا توجد بيانات تجريبية مضافة تلقائياً.

## النشر على Render

1. فك ضغط الملف.
2. أنشئ مستودع GitHub وارفع محتويات مجلد id-check-api. اجعل render.yaml في جذر المستودع.
3. في Render اختر New ثم Blueprint واربط المستودع.
4. راجع الخدمتين id-check-api وid-check-db ثم اضغط Deploy Blueprint.
5. بعد نجاح النشر افتح رابط خدمة id-check-api.
6. من Environment داخل الخدمة انسخ قيمة ADMIN_TOKEN. استخدمها في صفحة الخدمة لإضافة أول ID.
7. أدخل ID واضغط فحص الرقم.

هذه الإعدادات تستخدم Free للتجربة. قاعدة Render المجانية تنتهي بعد 30 يوماً. للاستمرار اختر خطة قاعدة بيانات مدفوعة أو اربط PostgreSQL خارجي عبر DATABASE_URL. خدمة الويب المجانية قد تتوقف عند عدم الاستخدام، لذلك قد يتأخر أول طلب.

لا ترسل كلمة سر الإدارة لتطبيق الموبايل. واجهة الفحص مفتوحة عبر الإنترنت في هذه النسخة. إذا كانت الأرقام حساسة، أضف تسجيل دخول للمستخدمين قبل استخدامها. رمز مشترك داخل تطبيق الموبايل لا يوفر حماية مناسبة.

## طلب تطبيق الموبايل

POST https://YOUR-SERVICE.onrender.com/api/check
Content-Type: application/json

```json
{"id":"00123"}
```

إذا كان موجوداً
```json
{"id":"00123","exists":true}
```

إذا لم يكن موجوداً
```json
{"id":"00123","exists":false}
```

النتيجتان HTTP 200. البيانات غير الصالحة HTTP 400. تعذر الوصول لقاعدة البيانات HTTP 503 ويجب أن يعرض التطبيق مشكلة اتصال، وليس أن الرقم غير موجود.

مثال JavaScript
```javascript
const response = await fetch(`${API_URL}/api/check`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ id: '00123' })
});
if (!response.ok) throw new Error('Request failed');
const { exists } = await response.json();
```

## الإدارة عبر API

POST /api/records لإضافة رقم. DELETE /api/records لحذفه.
نفس JSON السابق مع Authorization: Bearer YOUR_ADMIN_TOKEN.
الإضافة المتكررة لا تنشئ صفاً مكرراً. حد الطلب 4096 بايت. ID يقبل حروف إنجليزية وأرقاماً وشرطة وشرطة سفلية بطول 1 إلى 64.

## التشغيل المحلي

Python 3.11 أو أحدث. لا تحتاج تثبيت مكتبات للتجربة المحلية.

Windows PowerShell
```powershell
$env:ADMIN_TOKEN="choose-a-long-random-secret"
python app.py
```

macOS / Linux
```bash
export ADMIN_TOKEN='choose-a-long-random-secret'
python3 app.py
```

افتح http://localhost:8000. استخدم كلمة السر التي اخترتها عند إضافة الأرقام.
البيانات المحلية تحفظ في local.db، ولا ترفع هذا الملف إلى GitHub.

## التحقق

```bash
python3 -m unittest -v
```

الاختبارات تغطي الإضافة والفحص والحذف والصلاحيات والتحقق من المدخلات وحفظ الأصفار ومنع حقن SQL. الاختبارات تستخدم SQLite. اتصال PostgreSQL والنشر على Render يحتاجان اختباراً بعد النشر.
