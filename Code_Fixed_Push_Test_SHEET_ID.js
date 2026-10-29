/**
 * نظام الاستئذان - Staff-Permissions
 * النسخة المعدّلة: توجيه كادر إداري للنائب الإداري + تمييز vp_admin
 */

const SHEET_ID = '1pRrIRh7N---pGr5B3nrl7MF0ttE_S0p0TmI0QrNuxbk';
const REQUESTS_SHEET_NAME = 'Requests';
const EMPLOYEES_SHEET_NAME = 'Employees';

const PROP_AUTH_COORDINATOR = 'AUTH_COORDINATOR';
const PROP_AUTH_VP        = 'AUTH_VP';
const PROP_AUTH_VP_ADMIN  = 'AUTH_VP_ADMIN';
const PROP_AUTH_PRINCIPAL = 'AUTH_PRINCIPAL';
const PROP_AUTH_ADMIN     = 'AUTH_ADMIN';
const PROP_JOKER          = 'JOKER_PASSWORD';
const PROP_STAFF_EDIT     = 'STAFF_EDIT_PASSWORD';

const SESSION_TTL_SECONDS = 8 * 60 * 60;
const SUBSTITUTE_SESSION_TTL_SECONDS = 6 * 60 * 60;
const SUBSTITUTE_PASSWORD_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const REQUESTER_SESSION_TTL_SECONDS = 3 * 60 * 60;
const SUBSTITUTE_DECISION_LOCK_MS = 60 * 1000;

const DEFAULT_MONTHLY_BALANCE = 600;
const DIRECT_PRINCIPAL_NAME = 'أحمد إسماعيل عبد المنعم الدسوقي';

const REQUEST_HEADERS = [
  'requestId', 'employeeId', 'name', 'jobTitle', 'phone', 'email', 'subject',
  'permissionType', 'date', 'exitTime', 'returnTime', 'reason', 'coverage',
  'coverageDetails', 'duration', 'status', 'coordinatorStatus', 'vpStatus',
  'principalStatus', 'empId', 'coverageType', 'adminCoverage', 'adminSubstitute',
  'adminSubstituteEmpId', 'consent', 'rejectionReason', 'substituteApprovals',
  'coordinatorDate', 'substituteTokens'
];

const EMPLOYEE_HEADERS = [
  'id', 'name', 'jobTitle', 'employeeId', 'nationality', 'personalId',
  'phone', 'email', 'balance', 'active', 'updatedAt'
];

/* ==================== أدوات مساعدة ==================== */
function str_(v) { return v === null || v === undefined ? '' : String(v).trim(); }
function normalizeLoginId_(v) {
  return String(v || '').replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d)).replace(/\s/g, '');
}
function normalizeArabic_(v) {
  return String(v || '').toLowerCase()
    .replace(/[\u064B-\u065F\u0670]/g, '')
    .replace(/[أإآ]/g, 'ا').replace(/ة/g, 'ه').replace(/ى/g, 'ي')
    .replace(/\s+/g, ' ').trim();
}
function errorText_(e) { return String(e && e.message ? e.message : e); }
function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
function parseData_(raw) {
  if (raw && typeof raw === 'object') return raw;
  try { return JSON.parse(String(raw || '{}')); } catch (_) { return {}; }
}
function makeRequestId_() { return 'REQ-' + new Date().getTime(); }
function randomPassword_(len) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  const arr = new Uint8Array(len || 8);
  try { crypto.getRandomValues(arr); } catch (_) { for (let i = 0; i < len; i++) arr[i] = Math.floor(Math.random() * 256); }
  for (let i = 0; i < (len || 8); i++) out += chars[arr[i] % chars.length];
  return out;
}

/* ==================== المصادقة ==================== */
function getProp_(key) { return String(PropertiesService.getScriptProperties().getProperty(key) || ''); }

function verifyPassword_(role, password) {
  const r = str_(role), p = String(password == null ? '' : password);
  if (!r || !p) return false;
  const joker = getProp_(PROP_JOKER);
  if (joker && p === joker) return true;
  const map = {
    coordinator: PROP_AUTH_COORDINATOR, vp: PROP_AUTH_VP,
    vp_admin: PROP_AUTH_VP_ADMIN, principal: PROP_AUTH_PRINCIPAL, admin: PROP_AUTH_ADMIN
  };
  const propName = map[r];
  if (!propName) return false;
  const expected = getProp_(propName);
  return expected !== '' && expected === p;
}

function issueSession_(role) {
  const token = Utilities.getUuid() + '-' + Utilities.getUuid();
  CacheService.getScriptCache().put('sess_' + token, JSON.stringify({ role, issuedAt: Date.now() }), SESSION_TTL_SECONDS);
  return token;
}

function requireSession_(token, allowedRoles) {
  const t = str_(token);
  if (!t) throw new Error('UNAUTHORIZED');
  const raw = CacheService.getScriptCache().get('sess_' + t);
  if (!raw) throw new Error('UNAUTHORIZED');
  let payload;
  try { payload = JSON.parse(raw); } catch (_) { throw new Error('UNAUTHORIZED'); }
  const role = String(payload.role || '');
  if (!role) throw new Error('UNAUTHORIZED');
  if (Array.isArray(allowedRoles) && allowedRoles.length && !allowedRoles.includes(role)) throw new Error('UNAUTHORIZED');
  return payload;
}

function destroySession_(token) { const t = str_(token); if (t) CacheService.getScriptCache().remove('sess_' + t); }

function handleLogin_(p) {
  const role = str_(p.role);
  const password = String(p.password == null ? '' : p.password);
  const allowedRoles = ['coordinator', 'vp', 'vp_admin', 'principal', 'admin'];
  if (!allowedRoles.includes(role)) return json_({ success: false, message: 'الدور غير معروف.' });
  if (!verifyPassword_(role, password)) return json_({ success: false, message: 'كلمة المرور خاطئة!' });

  // احتفظ بالدور الحقيقي (vp_admin) — لا تحوّله إلى vp
  const token = issueSession_(role);
  return json_({ success: true, sessionToken: token, role: role, requestedRole: role });
}
function handleLogout_(p) { destroySession_(p.sessionToken); return json_({ success: true }); }
function handleValidateSession_(p) {
  try { const payload = requireSession_(p.sessionToken, null); return json_({ success: true, role: payload.role, issuedAt: payload.issuedAt }); }
  catch (e) { return json_({ success: false, message: 'UNAUTHORIZED' }); }
}
function handleRevealPasswords_(p) {
  const jokerInput = String(p.jokerPassword == null ? '' : p.jokerPassword);
  const jokerStored = getProp_(PROP_JOKER);
  if (!jokerInput || !jokerStored || jokerInput !== jokerStored) return json_({ success: false, message: 'كلمة مرور الجوكر غير صحيحة!' });
  return json_({ success: true, passwords: {
    coordinator: getProp_(PROP_AUTH_COORDINATOR), vp: getProp_(PROP_AUTH_VP),
    vp_admin: getProp_(PROP_AUTH_VP_ADMIN), principal: getProp_(PROP_AUTH_PRINCIPAL), admin: getProp_(PROP_AUTH_ADMIN)
  }});
}

function issueSubstituteSession_(reqId, employeeId) {
  const token = Utilities.getUuid() + '-' + Utilities.getUuid();
  CacheService.getScriptCache().put('subsess_' + token, JSON.stringify({ reqId: str_(reqId), employeeId: normalizeLoginId_(employeeId), issuedAt: Date.now() }), SUBSTITUTE_SESSION_TTL_SECONDS);
  return token;
}
function requireSubstituteSession_(token, reqId, employeeId) {
  const t = str_(token);
  if (!t) throw new Error('UNAUTHORIZED');
  const raw = CacheService.getScriptCache().get('subsess_' + t);
  if (!raw) throw new Error('UNAUTHORIZED');
  const payload = JSON.parse(raw);
  if (str_(payload.reqId) !== str_(reqId)) throw new Error('UNAUTHORIZED');
  if (normalizeLoginId_(payload.employeeId) !== normalizeLoginId_(employeeId)) throw new Error('UNAUTHORIZED');
  return payload;
}
function destroySubstituteSession_(token) {
  const t = str_(token);
  if (t) CacheService.getScriptCache().remove('subsess_' + t);
}

function issueRequesterSession_(reqId, employeeId) {
  const token = Utilities.getUuid() + '-' + Utilities.getUuid();
  CacheService.getScriptCache().put('reqsess_' + token,
    JSON.stringify({ reqId: str_(reqId), employeeId: normalizeLoginId_(employeeId), issuedAt: Date.now() }),
    REQUESTER_SESSION_TTL_SECONDS);
  return token;
}
function requireRequesterSession_(token, reqId, employeeId) {
  const t = str_(token);
  if (!t) throw new Error('UNAUTHORIZED');
  const raw = CacheService.getScriptCache().get('reqsess_' + t);
  if (!raw) throw new Error('UNAUTHORIZED');
  const payload = JSON.parse(raw);
  if (str_(payload.reqId) !== str_(reqId)) throw new Error('UNAUTHORIZED');
  if (normalizeLoginId_(payload.employeeId) !== normalizeLoginId_(employeeId)) throw new Error('UNAUTHORIZED');
  return payload;
}
function destroyRequesterSession_(token) {
  const t = str_(token);
  if (t) CacheService.getScriptCache().remove('reqsess_' + t);
}

/* ==================== مسار الموافقة ==================== */
function determineApprovalPath_(data) {
  const job = normalizeArabic_(data.jobTitle || '');
  const name = normalizeArabic_(data.name || '');
  const subject = str_(data.subject || '');
  const coverageType = str_(data.coverageType || 'حصص');

  // 1) المدير
  const principalNameNorm = normalizeArabic_(DIRECT_PRINCIPAL_NAME);
  const firstNameToken = principalNameNorm.split(' ')[0];
  if (name.includes(principalNameNorm) || (name.includes(firstNameToken) && name.includes('اسماعيل'))) {
    return { steps: ['principal'], initialStatus: 'vp_approved', isDirectToPrincipal: true, vpRole: '', reason: 'مقدم الطلب مدير المدرسة' };
  }
  if (/مدير\s*المدرسه|^مدير$/.test(job) || name.includes('مدير المدرسه')) {
    return { steps: ['principal'], initialStatus: 'vp_approved', isDirectToPrincipal: true, vpRole: '', reason: 'مقدم الطلب مدير المدرسة' };
  }

  // 2) النواب → مباشرة للمدير
  const isVP = /نائب.*(اكاديمي|اداري)|مساعد\s*مدير/.test(job);
  if (isVP) {
    return { steps: ['principal'], initialStatus: 'vp_approved', isDirectToPrincipal: true, vpRole: '', reason: 'مقدم الطلب أحد النواب' };
  }

  // 3) موظف إداري → النائب الإداري ثم المدير
  const jobIsAdmin = /اداري|اداريه|سكرتير|محاسب|امين مخزن|موظف استقبال/.test(job);
  if (coverageType === 'إداري' || subject === 'كادر إداري' || jobIsAdmin) {
    return {
      steps: ['vp_admin', 'principal'],
      initialStatus: 'vp_pending',
      vpRole: 'vp_admin',
      isDirectToPrincipal: false,
      reason: 'موظف إداري'
    };
  }

  // 4) منسق مادة → النائب الأكاديمي ثم المدير
  if (/منسق|منسقه|coordinator/.test(job) || job.includes('مشاريع') || job.includes('مسرح')) {
    return {
      steps: ['vp', 'principal'],
      initialStatus: 'vp_pending',
      vpRole: 'vp',
      isDirectToPrincipal: false,
      reason: 'منسق مادة'
    };
  }

  // 5) معلم → المنسق ثم النائب الأكاديمي ثم المدير
  return {
    steps: ['coordinator', 'vp', 'principal'],
    initialStatus: 'pending',
    vpRole: 'vp',
    isDirectToPrincipal: false,
    reason: 'معلم'
  };
}

function doGet(e) {
  const p = (e && e.parameter) || {};
  const action = String(p.action || '').trim();
  try {
    if (action === 'getBalance') return json_({ success: true, balance: getRemainingBalance_(p.empId || p.employeeId) });
    if (action === 'getLeaveSummary') return json_(getLeaveSummary_(p.empId || p.employeeId));
    if (action === 'getEmployees') {
      const employees = readEmployees_(true).map(publicEmployee_);
      return json_({ success: employees.length > 0, employees });
    }
    if (action === 'verifyEmployee') {
      const enteredId = normalizeLoginId_(p.id || p.employeeId || p.personalId);
      if (!enteredId) return json_({ success: false, message: 'أدخل الرقم الوظيفي أو الشخصي.' });
      const employee = readEmployees_(true).find(e =>
        normalizeLoginId_(e.employeeId) === enteredId || normalizeLoginId_(e.personalId) === enteredId);
      return employee ? json_({ success: true, employee: publicEmployee_(employee) }) : json_({ success: false, message: 'أنت غير مسجل بهذه المدرسة.' });
    }
    return json_({ status: 'Active' });
  } catch (err) { return json_({ success: false, message: errorText_(err) }); }
}

function doPost(e) {
  const p = (e && e.parameter) || {};
  const action = String(p.action || '').trim();
  try {
    switch (action) {
      case 'submit': return submitRequest_(p);
      case 'getRequest': return getRequestById_(p.reqId || p.requestId);

      case 'substituteLogin': return handleSubstituteLogin_(p);
      case 'substituteLogout': return handleSubstituteLogout_(p);
      case 'updateSubstituteApproval': return updateSubstituteApproval_(p.reqId || p.requestId, p.employeeId, p.decision, p.reason, p.substituteSession);

      case 'requesterLogin': return handleRequesterLogin_(p);
      case 'requesterLogout': return handleRequesterLogout_(p);
      case 'getRequesterSubstitutes': return handleGetRequesterSubstitutes_(p);
      case 'regenerateSubstitutePassword': return handleRegenerateSubstitutePassword_(p);
      case 'getRequesterSubstitutesByEmp': return handleGetRequesterSubstitutesByEmp_(p);
      case 'regenerateSubstitutePasswordByEmp': return handleRegenerateSubstitutePasswordByEmp_(p);

      case 'login': return handleLogin_(p);
      case 'logout': return handleLogout_(p);
      case 'validateSession': return handleValidateSession_(p);
      case 'revealPasswords': return handleRevealPasswords_(p);

      case 'updateStatus':
        requireSession_(p.sessionToken, ['coordinator', 'vp', 'vp_admin', 'principal']);
        return updateRequestStatus_(p.reqId || p.requestId, p.role, p.decision, p.reason);

      case 'getStats':
        requireSession_(p.sessionToken, ['admin', 'coordinator', 'vp', 'vp_admin', 'principal']);
        return getAdminStats_();

      case 'getRequests':
        requireSession_(p.sessionToken, ['admin', 'coordinator', 'vp', 'vp_admin', 'principal']);
        return getAllRequests_();

      case 'getEmployeesAdmin':
        requireSession_(p.sessionToken, ['admin']); requireEmployeeAdminKey_(p.adminKey);
        return json_({ success: true, employees: readEmployees_(false) });
      case 'addEmployee':
        requireSession_(p.sessionToken, ['admin']); requireEmployeeAdminKey_(p.adminKey);
        return addEmployee_(parseData_(p.data));
      case 'updateEmployee':
        requireSession_(p.sessionToken, ['admin']); requireEmployeeAdminKey_(p.adminKey);
        return updateEmployee_(parseData_(p.data));
      case 'deleteEmployee':
        requireSession_(p.sessionToken, ['admin']); requireEmployeeAdminKey_(p.adminKey);
        return disableEmployee_(parseData_(p.data));

      default: return json_({ success: false, message: 'الإجراء غير معروف: ' + action });
    }
  } catch (err) {
    const msg = errorText_(err);
    if (msg === 'UNAUTHORIZED') return json_({ success: false, code: 'UNAUTHORIZED', message: 'الجلسة غير صالحة أو منتهية. أعد تسجيل الدخول.' });
    return json_({ success: false, message: msg });
  }
}

function publicEmployee_(e) {
  return { id: e.id, name: e.name, jobTitle: e.jobTitle, employeeId: e.employeeId,
    nationality: e.nationality, personalId: e.personalId, phone: e.phone, email: e.email,
    active: e.active, balance: e.balance };
}

function submitRequest_(p) {
  const data = parseData_(p.data);
  const employeeId = str_(data.employeeId || data.empId);
  const name = str_(data.name);
  if (!employeeId || !name) throw new Error('الرقم الوظيفي واسم الموظف مطلوبان.');

  const isLeave = str_(data.permissionType) === 'طلب إجازة';
  let leaveDetails = {};
  if (isLeave) {
    try { leaveDetails = typeof data.coverageDetails === 'string' ? JSON.parse(data.coverageDetails) : (data.coverageDetails || {}); }
    catch (_) { leaveDetails = {}; }
    const leaveType = str_(leaveDetails.leaveType);
    const allowedLeaveTypes = ['عارضة', 'مرضية', 'تعاطفية', 'بدون راتب', 'زواج', 'حج', 'مرافق مريض', 'أخرى'];
    if (!allowedLeaveTypes.includes(leaveType)) throw new Error('نوع الإجازة غير معروف.');
    if (!leaveDetails.startDate || !leaveDetails.endDate || !str_(leaveDetails.reason)) throw new Error('بيانات طلب الإجازة غير مكتملة.');
    if (new Date(leaveDetails.endDate) < new Date(leaveDetails.startDate)) throw new Error('تاريخ نهاية الإجازة يسبق تاريخ البداية.');
    if (leaveType === 'زواج' && Number(leaveDetails.days || 0) > 15) throw new Error('الحد الأقصى لإجازة الزواج 15 يومًا.');
    if (leaveType === 'حج' && !leaveIsAtMostOneMonth_(leaveDetails.startDate, leaveDetails.endDate)) throw new Error('مدة إجازة الحج لا تتجاوز شهرًا واحدًا.');
    if (leaveType === 'عارضة') {
      const startYear = new Date(leaveDetails.startDate + 'T12:00:00').getFullYear();
      const endYear = new Date(leaveDetails.endDate + 'T12:00:00').getFullYear();
      for (let y = startYear; y <= endYear; y++) {
        const requestedInYear = leaveDaysInYear_(leaveDetails.startDate, leaveDetails.endDate, y);
        const usedInYear = getCasualApprovedDaysInYear_(employeeId, y);
        if (usedInYear + requestedInYear > 10) throw new Error('يتجاوز الطلب رصيد الإجازات العارضة المتاح للسنة ' + y + '. المتبقي: ' + Math.max(0, 10 - usedInYear) + ' يومًا.');
      }
    }
    if (['زواج','حج'].includes(leaveType)) {
      const alreadyUsed = requestsAsObjects_().some(x => {
        const d = x.data;
        if (str_(d.employeeId || d.empId) !== employeeId || d.status !== 'principal_approved' || str_(d.permissionType) !== 'طلب إجازة') return false;
        let info = {}; try { info = typeof d.coverageDetails === 'string' ? JSON.parse(d.coverageDetails) : (d.coverageDetails || {}); } catch (_) {}
        return str_(info.leaveType) === leaveType;
      });
      if (alreadyUsed) throw new Error(leaveType === 'زواج' ? 'توجد إجازة زواج معتمدة سابقًا لهذا الموظف.' : 'توجد إجازة حج معتمدة سابقًا لهذا الموظف.');
    }
  }

  const lock = LockService.getScriptLock();
  lock.waitLock(15000);
  try {
    const sh = requestsSheet_();
    const map = requestColumnMap_(sh);
    const requestId = makeRequestId_();
    const permissionType = str_(data.permissionType || data.type);
    const coverageType = str_(data.coverageType || 'حصص');
    const subject = str_(data.subject || '');

    const pathInfo = determineApprovalPath_(data);
    const initialStatus = pathInfo.initialStatus;

    const substituteApprovals = buildSubstituteApprovals_(data, coverageType);
    const substituteTokens = substituteApprovals.map(a => ({
      employeeId: a.employeeId, name: a.name,
      password: randomPassword_(8),
      createdAt: Date.now(),
      expiresAt: Date.now() + SUBSTITUTE_PASSWORD_TTL_MS,
      used: false
    }));

    let emailFromEmployees = '';
    try {
      const emp = readEmployees_(false).find(x =>
        normalizeLoginId_(x.employeeId) === normalizeLoginId_(employeeId) ||
        normalizeLoginId_(x.personalId) === normalizeLoginId_(employeeId));
      if (emp && emp.email) emailFromEmployees = str_(emp.email);
    } catch (_) {}
    const emailFinal = emailFromEmployees || str_(data.email);

    // حفظ مسار الموافقة داخل coverageDetails لقراءته لاحقاً
    let cdObj = {};
    try {
      cdObj = typeof data.coverageDetails === 'string'
        ? JSON.parse(data.coverageDetails || '{}')
        : (data.coverageDetails || {});
      if (Array.isArray(cdObj)) cdObj = { coverageArray: cdObj };
    } catch (_) { cdObj = {}; }
    cdObj._approvalPath = {
      steps: pathInfo.steps,
      vpRole: pathInfo.vpRole || '',
      reason: pathInfo.reason || ''
    };
    const coverageDetailsFinal = JSON.stringify(cdObj);

    const row = new Array(Math.max(sh.getLastColumn(), REQUEST_HEADERS.length)).fill('');
    const values = {
      requestId, employeeId, name,
      jobTitle: str_(data.jobTitle), phone: str_(data.phone), email: emailFinal,
      subject, permissionType, date: str_(data.date),
      exitTime: str_(data.exitTime || data.exit), returnTime: str_(data.returnTime || data.return),
      reason: str_(data.reason), coverage: str_(data.coverage),
      coverageDetails: coverageDetailsFinal, duration: Number(data.duration || 0) || 0,
      status: initialStatus,
      coordinatorStatus: pathInfo.steps.includes('coordinator') ? 'pending' : 'not_required',
      vpStatus: (pathInfo.steps.includes('vp') || pathInfo.steps.includes('vp_admin')) ? 'pending' : 'not_required',
      principalStatus: 'pending',
      empId: employeeId, coverageType,
      adminCoverage: str_(data.adminCoverage),
      adminSubstitute: str_(data.adminSubstitute),
      adminSubstituteEmpId: str_(data.adminSubstituteEmpId),
      consent: data.consent === true || String(data.consent).toLowerCase() === 'true',
      rejectionReason: '',
      substituteApprovals: JSON.stringify(substituteApprovals),
      substituteTokens: JSON.stringify(substituteTokens)
    };
    REQUEST_HEADERS.forEach(key => { if (map[key] !== undefined) row[map[key]] = values[key] == null ? '' : values[key]; });
    sh.appendRow(row);

    return json_({
      success: true,
      requestId,
      approvalPath: pathInfo,
      substituteCredentials: substituteTokens.map(t => ({
        employeeId: t.employeeId, name: t.name, tempPassword: t.password
      }))
    });
  } finally {
    lock.releaseLock();
  }
}

function updateRequestStatus_(requestId, role, decision, reason) {
  const id = str_(requestId);
  const userRole = str_(role);
  const choice = str_(decision).toLowerCase();
  const rejectReason = str_(reason);
  if (!id || !['coordinator', 'vp', 'vp_admin', 'principal'].includes(userRole) || !['approved', 'rejected'].includes(choice)) {
    throw new Error('بيانات غير صالحة.');
  }
  const sh = requestsSheet_();
  const map = requestColumnMap_(sh);
  const item = requestsAsObjects_().find(x => x.data.requestId === id);
  if (!item) return json_({ success: false, message: 'لم يتم العثور على الطلب.' });
  const requestData = item.data;
  const isLeave = str_(requestData.permissionType) === 'طلب إجازة';

  let leaveDetails = {};
  if (isLeave) {
    try { leaveDetails = typeof requestData.coverageDetails === 'string' ? JSON.parse(requestData.coverageDetails || '{}') : (requestData.coverageDetails || {}); }
    catch (_) { leaveDetails = {}; }
  }

  // تحديد النائب المطلوب من مسار الطلب
  let detailsObj = {};
  try {
    detailsObj = typeof requestData.coverageDetails === 'string'
      ? JSON.parse(requestData.coverageDetails || '{}')
      : (requestData.coverageDetails || {});
  } catch (_) { detailsObj = {}; }
  const requiredVpRole = (detailsObj._approvalPath && detailsObj._approvalPath.vpRole) || 'vp';

  // منع اعتماد النائب غير المختص
  if ((userRole === 'vp' || userRole === 'vp_admin') && userRole !== requiredVpRole) {
    throw new Error('هذا الطلب مخصص لاعتماد ' + (requiredVpRole === 'vp_admin' ? 'النائب الإداري' : 'النائب الأكاديمي') + ' فقط.');
  }

  const isCasualLeave = isLeave && str_(leaveDetails.leaveType) === 'عارضة';
  if (isCasualLeave && choice === 'approved' && userRole !== 'principal' &&
      (leaveDetails.coverageRequired === true || String(leaveDetails.coverageRequired).toLowerCase() === 'true')) {
    const leaveCoverage = leaveDetails.leaveCoverage;
    const approvals = getSubstituteApprovals_(requestData);
    const allSubstitutesApproved = Array.isArray(leaveCoverage) && leaveCoverage.length > 0 &&
      Array.isArray(approvals) && approvals.length > 0 &&
      leaveCoverage.every(coverage => {
        const empId = normalizeLoginId_(coverage.substituteEmpId || coverage.employeeId);
        if (!empId) return false;
        const approval = approvals.find(a => normalizeLoginId_(a.employeeId) === empId);
        return approval && approval.status === 'approved';
      });
    if (!allSubstitutesApproved) throw new Error('لا يمكن اعتماد الإجازة العارضة قبل موافقة جميع البدلاء.');
  }
  if (!isCasualLeave && userRole === 'coordinator' && choice === 'approved') {
    const approvals = getSubstituteApprovals_(requestData);
    const pending = approvals.filter(a => a.status !== 'approved');
    if (pending.length) {
      const names = pending.map(a => a.name + (a.status === 'rejected' ? ' (رفض)' : ' (بانتظار الموافقة)')).join('، ');
      throw new Error('لا يمكن اعتماد الطلب قبل موافقة جميع البدلاء. الحالات غير المكتملة: ' + names);
    }
  }

  let nextStatus = requestData.status;
  if (choice === 'rejected') {
    nextStatus = userRole === 'vp_admin' ? 'vp_rejected' : (userRole + '_rejected');
  } else if (userRole === 'coordinator') {
    nextStatus = 'coordinator_approved';
  } else if (userRole === 'vp' || userRole === 'vp_admin') {
    nextStatus = 'vp_approved';
  } else {
    nextStatus = 'principal_approved';
  }

  sh.getRange(item.rowNumber, map.status + 1).setValue(nextStatus);
  if (userRole === 'coordinator' && choice === 'approved' && map.coordinatorDate !== undefined) {
    sh.getRange(item.rowNumber, map.coordinatorDate + 1).setValue(new Date());
  }
  if (rejectReason && map.rejectionReason !== undefined) {
    sh.getRange(item.rowNumber, map.rejectionReason + 1).setValue(rejectReason);
  }
  return json_({ success: true, newStatus: nextStatus });
}

function handleSubstituteLogin_(p) {
  const reqId = str_(p.reqId || p.requestId);
  const employeeId = normalizeLoginId_(p.employeeId);
  const password = String(p.password == null ? '' : p.password).trim();
  if (!reqId || !employeeId || !password) {
    return json_({ success: false, message: 'يرجى إدخال رقم الطلب والرقم الوظيفي وكلمة المرور المؤقتة.' });
  }
  const item = requestsAsObjects_().find(x => str_(x.data.requestId) === reqId);
  if (!item) return json_({ success: false, message: 'رقم الطلب غير موجود.' });
  const reqOwnerId = normalizeLoginId_(item.data.employeeId || item.data.empId || '');
  const tokens = getSubstituteTokens_(item.data);
  const token = tokens.find(t => normalizeLoginId_(t.employeeId) === employeeId);

  if (!token) {
    if (reqOwnerId && employeeId === reqOwnerId) {
      const reqSession = issueRequesterSession_(reqId, employeeId);
      return json_({ success: true, mode: 'requester', requesterSession: reqSession, reqId, employeeId, message: 'تم التعرف عليك كمقدم الطلب.' });
    }
    return json_({ success: false, message: 'أنت غير مسند كبديل لهذا الطلب.' });
  }

  if (token.used === true) {
    if (reqOwnerId && employeeId === reqOwnerId) {
      const reqSession = issueRequesterSession_(reqId, employeeId);
      return json_({ success: true, mode: 'requester', requesterSession: reqSession, reqId, employeeId, message: 'تم التعرف عليك كمقدم الطلب.' });
    }
    const approvals = getSubstituteApprovals_(item.data);
    const mine = approvals.find(a => normalizeLoginId_(a.employeeId) === employeeId);
    const isRejected = mine && mine.status === 'rejected';
    if (!isRejected) {
      return json_({ success: false, message: 'تم استخدام كلمة المرور المؤقتة سابقًا. اطلب كلمة جديدة من مقدم الطلب.' });
    }
    return json_({
      success: false,
      code: 'PASSWORD_USED_AND_REJECTED',
      message: 'سبق استخدام كلمة المرور ورفضك التغطية. اطلب من مقدم الطلب إعادة توليد كلمة مرور جديدة لتغيير القرار.'
    });
  }

  if (Date.now() > Number(token.expiresAt || 0)) {
    if (reqOwnerId && employeeId === reqOwnerId) {
      const reqSession = issueRequesterSession_(reqId, employeeId);
      return json_({ success: true, mode: 'requester', requesterSession: reqSession, reqId, employeeId, message: 'تم التعرف عليك كمقدم الطلب.' });
    }
    return json_({ success: false, message: 'انتهت صلاحية كلمة المرور المؤقتة. اطلب كلمة جديدة من مقدم الطلب.' });
  }

  if (String(token.password) !== password) {
    if (reqOwnerId && employeeId === reqOwnerId) {
      const reqSession = issueRequesterSession_(reqId, employeeId);
      return json_({ success: true, mode: 'requester', requesterSession: reqSession, reqId, employeeId, message: 'تم التعرف عليك كمقدم الطلب.' });
    }
    return json_({ success: false, message: 'كلمة المرور المؤقتة غير صحيحة.' });
  }

  token.used = true;
  token.usedAt = new Date().toISOString();
  const sh = requestsSheet_();
  const map = requestColumnMap_(sh);
  sh.getRange(item.rowNumber, map.substituteTokens + 1).setValue(JSON.stringify(tokens));

  const session = issueSubstituteSession_(reqId, employeeId);
  const approvals = getSubstituteApprovals_(item.data);
  const mine = approvals.find(a => normalizeLoginId_(a.employeeId) === employeeId);

  return json_({
    success: true, mode: 'substitute',
    substituteSession: session, reqId, employeeId,
    name: mine ? mine.name : (token.name || ''),
    approvalStatus: mine ? (mine.status || 'pending') : 'pending',
    canChangeDecision: !!(mine && mine.status === 'rejected')
  });
}

function handleSubstituteLogout_(p) {
  destroySubstituteSession_(p.substituteSession);
  return json_({ success: true });
}

function handleRequesterLogin_(p) {
  const reqId = str_(p.reqId || p.requestId);
  const employeeId = normalizeLoginId_(p.employeeId);
  if (!reqId || !employeeId) return json_({ success: false, message: 'رقم الطلب والرقم الوظيفي مطلوبان.' });
  const item = requestsAsObjects_().find(x => str_(x.data.requestId) === reqId);
  if (!item) return json_({ success: false, message: 'رقم الطلب غير موجود.' });
  const reqOwnerId = normalizeLoginId_(item.data.employeeId || item.data.empId || '');
  if (!reqOwnerId || reqOwnerId !== employeeId) return json_({ success: false, message: 'أنت لست مقدم هذا الطلب.' });
  const reqSession = issueRequesterSession_(reqId, employeeId);
  return json_({ success: true, requesterSession: reqSession, reqId, employeeId, name: item.data.name || '' });
}
function handleRequesterLogout_(p) { destroyRequesterSession_(p.requesterSession); return json_({ success: true }); }

function handleGetRequesterSubstitutes_(p) {
  const reqId = str_(p.reqId || p.requestId);
  const employeeId = normalizeLoginId_(p.employeeId);
  const session = str_(p.requesterSession);
  if (!reqId || !employeeId) throw new Error('بيانات ناقصة.');
  requireRequesterSession_(session, reqId, employeeId);

  const item = requestsAsObjects_().find(x => str_(x.data.requestId) === reqId);
  if (!item) throw new Error('لم يتم العثور على الطلب.');

  const approvals = getSubstituteApprovals_(item.data);
  const tokens = getSubstituteTokens_(item.data);
  const now = Date.now();

  const rows = approvals.map(a => {
    const t = tokens.find(x => normalizeLoginId_(x.employeeId) === normalizeLoginId_(a.employeeId));
    let pwdStatus = 'none';
    if (t) {
      if (t.used === true) pwdStatus = 'used';
      else if (Number(t.expiresAt || 0) < now) pwdStatus = 'expired';
      else pwdStatus = 'active';
    }
    return {
      employeeId: a.employeeId, name: a.name,
      approvalStatus: a.status || 'pending', approvalReason: a.reason || '',
      passwordStatus: pwdStatus, expiresAt: t ? t.expiresAt : 0,
      canRegenerate: (a.status || 'pending') !== 'approved'
    };
  });

  return json_({
    success: true, reqId,
    requestName: item.data.name || '',
    permissionType: item.data.permissionType || '',
    status: item.data.status || '',
    substitutes: rows
  });
}

function handleRegenerateSubstitutePassword_(p) {
  const reqId = str_(p.reqId || p.requestId);
  const employeeId = normalizeLoginId_(p.employeeId);
  const substituteEmpId = normalizeLoginId_(p.substituteEmpId);
  const session = str_(p.requesterSession);
  if (!reqId || !employeeId || !substituteEmpId) throw new Error('بيانات ناقصة.');
  requireRequesterSession_(session, reqId, employeeId);

  const sh = requestsSheet_();
  const map = requestColumnMap_(sh);
  const item = requestsAsObjects_().find(x => str_(x.data.requestId) === reqId);
  if (!item) throw new Error('لم يتم العثور على الطلب.');

  const approvals = getSubstituteApprovals_(item.data);
  const target = approvals.find(a => normalizeLoginId_(a.employeeId) === substituteEmpId);
  if (!target) throw new Error('البديل غير مسند لهذا الطلب.');
  if (target.status === 'approved') throw new Error('لا يمكن إعادة توليد كلمة مرور لبديل وافق مسبقًا على التغطية.');
  if (target.status === 'rejected') { target.status = 'pending'; target.reason = ''; target.reopenedAt = new Date().toISOString(); }

  const tokens = getSubstituteTokens_(item.data);
  const existingIdx = tokens.findIndex(t => normalizeLoginId_(t.employeeId) === substituteEmpId);
  const newToken = {
    employeeId: target.employeeId, name: target.name,
    password: randomPassword_(8),
    createdAt: Date.now(),
    expiresAt: Date.now() + SUBSTITUTE_PASSWORD_TTL_MS,
    used: false
  };
  if (existingIdx >= 0) tokens[existingIdx] = newToken;
  else tokens.push(newToken);

  sh.getRange(item.rowNumber, map.substituteTokens + 1).setValue(JSON.stringify(tokens));
  sh.getRange(item.rowNumber, map.substituteApprovals + 1).setValue(JSON.stringify(approvals));

  return json_({
    success: true, reqId,
    substituteEmpId: target.employeeId,
    substituteName: target.name,
    tempPassword: newToken.password,
    expiresAt: newToken.expiresAt
  });
}

function handleGetRequesterSubstitutesByEmp_(p) {
  const reqId = str_(p.reqId || p.requestId);
  const employeeId = normalizeLoginId_(p.employeeId);
  if (!reqId || !employeeId) throw new Error('رقم الطلب والرقم الوظيفي مطلوبان.');

  const item = requestsAsObjects_().find(x => str_(x.data.requestId) === reqId);
  if (!item) throw new Error('لم يتم العثور على الطلب.');

  const reqOwnerId = normalizeLoginId_(item.data.employeeId || item.data.empId || '');
  if (!reqOwnerId || reqOwnerId !== employeeId) {
    throw new Error('أنت لست مقدم هذا الطلب. لا يمكنك إدارة البدلاء.');
  }

  const approvals = getSubstituteApprovals_(item.data);
  const tokens = getSubstituteTokens_(item.data);
  const now = Date.now();

  const rows = approvals.map(a => {
    const t = tokens.find(x => normalizeLoginId_(x.employeeId) === normalizeLoginId_(a.employeeId));
    let pwdStatus = 'none';
    if (t) {
      if (t.used === true) pwdStatus = 'used';
      else if (Number(t.expiresAt || 0) < now) pwdStatus = 'expired';
      else pwdStatus = 'active';
    }
    return {
      employeeId: a.employeeId, name: a.name,
      approvalStatus: a.status || 'pending', approvalReason: a.reason || '',
      passwordStatus: pwdStatus, expiresAt: t ? t.expiresAt : 0,
      canRegenerate: (a.status || 'pending') !== 'approved'
    };
  });

  return json_({
    success: true, reqId,
    requestName: item.data.name || '',
    permissionType: item.data.permissionType || '',
    status: item.data.status || '',
    substitutes: rows
  });
}

function handleRegenerateSubstitutePasswordByEmp_(p) {
  const reqId = str_(p.reqId || p.requestId);
  const employeeId = normalizeLoginId_(p.employeeId);
  const substituteEmpId = normalizeLoginId_(p.substituteEmpId);
  if (!reqId || !employeeId || !substituteEmpId) throw new Error('بيانات ناقصة.');

  const sh = requestsSheet_();
  const map = requestColumnMap_(sh);
  const item = requestsAsObjects_().find(x => str_(x.data.requestId) === reqId);
  if (!item) throw new Error('لم يتم العثور على الطلب.');

  const reqOwnerId = normalizeLoginId_(item.data.employeeId || item.data.empId || '');
  if (!reqOwnerId || reqOwnerId !== employeeId) throw new Error('أنت لست مقدم هذا الطلب.');

  const approvals = getSubstituteApprovals_(item.data);
  const target = approvals.find(a => normalizeLoginId_(a.employeeId) === substituteEmpId);
  if (!target) throw new Error('البديل غير مسند لهذا الطلب.');
  if (target.status === 'approved') throw new Error('لا يمكن إعادة توليد كلمة مرور لبديل وافق مسبقًا على التغطية.');
  if (target.status === 'rejected') { target.status = 'pending'; target.reason = ''; target.reopenedAt = new Date().toISOString(); }

  const tokens = getSubstituteTokens_(item.data);
  const existingIdx = tokens.findIndex(t => normalizeLoginId_(t.employeeId) === substituteEmpId);
  const newToken = {
    employeeId: target.employeeId, name: target.name,
    password: randomPassword_(8),
    createdAt: Date.now(),
    expiresAt: Date.now() + SUBSTITUTE_PASSWORD_TTL_MS,
    used: false
  };
  if (existingIdx >= 0) tokens[existingIdx] = newToken;
  else tokens.push(newToken);

  sh.getRange(item.rowNumber, map.substituteTokens + 1).setValue(JSON.stringify(tokens));
  sh.getRange(item.rowNumber, map.substituteApprovals + 1).setValue(JSON.stringify(approvals));

  return json_({
    success: true, reqId,
    substituteEmpId: target.employeeId,
    substituteName: target.name,
    tempPassword: newToken.password,
    expiresAt: newToken.expiresAt
  });
}

function buildSubstituteApprovals_(data, coverageType) {
  const people = [];
  let details = data.coverageDetails || [];
  try { if (typeof details === 'string') details = JSON.parse(details); } catch (_) { details = []; }
  let rows = Array.isArray(details) ? details : [];
  if (!Array.isArray(details) && details && details.requestKind === 'leave' && Array.isArray(details.leaveCoverage)) rows = details.leaveCoverage;
  rows.forEach(x => {
    const employeeId = str_(x.substituteEmpId || x.employeeId);
    const name = str_(x.substituteTeacher || x.teacher || x.name);
    if (employeeId && name) people.push({ employeeId, name, role: 'teacher', status: 'pending', reason: '' });
  });
  if (coverageType === 'إداري' && str_(data.adminSubstituteEmpId) && str_(data.adminSubstitute)) {
    people.push({ employeeId: str_(data.adminSubstituteEmpId), name: str_(data.adminSubstitute), role: 'admin', status: 'pending', reason: '' });
  }
  const unique = {};
  people.forEach(a => { if (!unique[normalizeLoginId_(a.employeeId)]) unique[normalizeLoginId_(a.employeeId)] = a; });
  return Object.keys(unique).map(k => unique[k]);
}

function getSubstituteApprovals_(data) {
  let approvals = data.substituteApprovals || [];
  try { if (typeof approvals === 'string') approvals = JSON.parse(approvals); } catch (_) { approvals = []; }
  if (Array.isArray(approvals) && approvals.length) return approvals;
  return buildSubstituteApprovals_(data, str_(data.coverageType || 'حصص'));
}

function getSubstituteTokens_(data) {
  let tokens = data.substituteTokens || [];
  try { if (typeof tokens === 'string') tokens = JSON.parse(tokens); } catch (_) { tokens = []; }
  return Array.isArray(tokens) ? tokens : [];
}

function updateSubstituteApproval_(requestId, employeeId, decision, reason, substituteSession) {
  const id = str_(requestId);
  const empId = normalizeLoginId_(employeeId);
  const choice = str_(decision).toLowerCase();
  if (!id || !empId || !['approved', 'rejected'].includes(choice)) throw new Error('بيانات موافقة البديل غير مكتملة.');

  requireSubstituteSession_(substituteSession, id, empId);

  const sh = requestsSheet_();
  const map = requestColumnMap_(sh);
  const item = requestsAsObjects_().find(x => str_(x.data.requestId) === id);
  if (!item) throw new Error('لم يتم العثور على الطلب.');
  const approvals = getSubstituteApprovals_(item.data);
  const mine = approvals.find(a => normalizeLoginId_(a.employeeId) === empId);
  if (!mine) throw new Error('هذا الطلب غير مسند إليك كبديل.');

  const currentStatus = mine.status || 'pending';
  if (currentStatus === 'approved') throw new Error('سبق تسجيل موافقتك ولا يمكن تغييرها.');
  if (currentStatus === 'rejected') {
    const decidedAt = Number(mine.updatedAtMs || 0);
    const now = Date.now();
    if (decidedAt && now - decidedAt < SUBSTITUTE_DECISION_LOCK_MS) {
      throw new Error('لا يمكن تغيير القرار خلال الدقيقة الأولى بعد الرفض. أعد المحاولة لاحقًا.');
    }
  }

  mine.status = choice;
  mine.reason = str_(reason);
  mine.updatedAt = new Date().toISOString();
  mine.updatedAtMs = Date.now();
  sh.getRange(item.rowNumber, map.substituteApprovals + 1).setValue(JSON.stringify(approvals));

  destroySubstituteSession_(substituteSession);
  return json_({
    success: true,
    message: choice === 'approved' ? 'تم تسجيل موافقتك بنجاح.' : 'تم تسجيل رفض التغطية.',
    substituteApprovals: approvals
  });
}

function getRemainingBalance_(employeeId) {
  const id = str_(employeeId);
  if (!id) return DEFAULT_MONTHLY_BALANCE;
  const now = new Date();
  let used = 0;
  requestsAsObjects_().forEach(item => {
    const d = item.data;
    if (str_(d.employeeId || d.empId) !== id) return;
    if (d.status !== 'principal_approved') return;
    if (d.permissionType === 'ورشة تعليمية' || d.permissionType === 'مهمة رسمية') return;
    if (d.permissionType === 'طلب إجازة') return;
    const dateObj = new Date(d.date);
    if (isNaN(dateObj.getTime())) return;
    if (dateObj.getFullYear() === now.getFullYear() && dateObj.getMonth() === now.getMonth()) used += Number(d.duration || 0);
  });
  return Math.max(0, DEFAULT_MONTHLY_BALANCE - used);
}

function getCasualApprovedDaysInYear_(employeeId, year) {
  const id = normalizeLoginId_(employeeId);
  let used = 0;
  requestsAsObjects_().forEach(item => {
    const d = item.data;
    if (normalizeLoginId_(d.employeeId || d.empId) !== id || d.permissionType !== 'طلب إجازة' || d.status !== 'principal_approved') return;
    let info = {}; try { info = typeof d.coverageDetails === 'string' ? JSON.parse(d.coverageDetails) : (d.coverageDetails || {}); } catch (_) {}
    if (str_(info.leaveType) === 'عارضة') used += leaveDaysInYear_(info.startDate, info.endDate, year);
  });
  return used;
}

function getLeaveSummary_(employeeId) {
  const id = normalizeLoginId_(employeeId);
  if (!id) return { success: false, message: 'الرقم الوظيفي مطلوب.' };
  const year = new Date().getFullYear();
  let casualUsed = 0, otherApprovedCount = 0;
  const counts = {};
  requestsAsObjects_().forEach(item => {
    const d = item.data;
    if (normalizeLoginId_(d.employeeId || d.empId) !== id || d.permissionType !== 'طلب إجازة' || d.status !== 'principal_approved') return;
    let info = {}; try { info = typeof d.coverageDetails === 'string' ? JSON.parse(d.coverageDetails) : (d.coverageDetails || {}); } catch (_) {}
    const type = str_(info.leaveType || 'أخرى');
    counts[type] = (counts[type] || 0) + 1;
    if (type === 'عارضة') casualUsed += leaveDaysInYear_(info.startDate, info.endDate, year);
    else otherApprovedCount++;
  });
  casualUsed = Math.min(10, casualUsed);
  return { success: true, year, casualEntitlement: 10, casualUsed, casualRemaining: Math.max(0, 10 - casualUsed), otherApprovedCount, counts };
}

function leaveIsAtMostOneMonth_(startValue, endValue) {
  if (!startValue || !endValue) return false;
  const start = new Date(String(startValue) + 'T12:00:00');
  const end = new Date(String(endValue) + 'T12:00:00');
  if (isNaN(start.getTime()) || isNaN(end.getTime()) || end < start) return false;
  const nextMonth = new Date(start.getFullYear(), start.getMonth() + 1, 1, 12);
  const lastDayNextMonth = new Date(nextMonth.getFullYear(), nextMonth.getMonth() + 1, 0, 12).getDate();
  const clamped = new Date(nextMonth.getFullYear(), nextMonth.getMonth(), Math.min(start.getDate(), lastDayNextMonth), 12);
  const maxEnd = new Date(clamped.getTime() - 86400000);
  return end <= maxEnd;
}

function leaveDaysInYear_(startValue, endValue, year) {
  if (!startValue || !endValue) return 0;
  const start = new Date(String(startValue) + 'T12:00:00');
  const end = new Date(String(endValue) + 'T12:00:00');
  if (isNaN(start.getTime()) || isNaN(end.getTime()) || end < start) return 0;
  const a = new Date(Math.max(start.getTime(), new Date(year, 0, 1, 12).getTime()));
  const b = new Date(Math.min(end.getTime(), new Date(year, 11, 31, 12).getTime()));
  return b < a ? 0 : Math.floor((b - a) / 86400000) + 1;
}

function spreadsheet_() { return SpreadsheetApp.openById(SHEET_ID); }

function requestsSheet_() {
  const ss = spreadsheet_();
  let sh = ss.getSheetByName(REQUESTS_SHEET_NAME);
  if (!sh) {
    sh = ss.insertSheet(REQUESTS_SHEET_NAME);
    sh.getRange(1, 1, 1, REQUEST_HEADERS.length).setValues([REQUEST_HEADERS]);
    sh.setFrozenRows(1);
  }
  const currentHeaders = sh.getRange(1, 1, 1, Math.max(sh.getLastColumn(), 1)).getDisplayValues()[0].map(x => String(x).trim());
  REQUEST_HEADERS.forEach(h => {
    if (!currentHeaders.some(x => x.toLowerCase() === h.toLowerCase())) {
      const col = sh.getLastColumn() + 1;
      sh.getRange(1, col).setValue(h);
      currentHeaders.push(h);
    }
  });
  return sh;
}

function employeesSheet_() {
  const ss = spreadsheet_();
  let sh = ss.getSheetByName(EMPLOYEES_SHEET_NAME);
  if (!sh) {
    sh = ss.insertSheet(EMPLOYEES_SHEET_NAME);
    sh.getRange(1, 1, 1, EMPLOYEE_HEADERS.length).setValues([EMPLOYEE_HEADERS]);
    sh.setFrozenRows(1);
  }
  return sh;
}

function requestColumnMap_(sh) {
  // Ensure every required field has a real header. Missing headers are appended,
  // never silently mapped onto another field (which can make substitute decisions
  // appear as pending or overwrite unrelated request data).
  let lastCol = Math.max(sh.getLastColumn(), 1);
  let headers = sh.getRange(1, 1, 1, lastCol).getDisplayValues()[0].map(h => String(h || '').trim());
  REQUEST_HEADERS.forEach(name => {
    const exists = headers.some(h => h.toLowerCase() === name.toLowerCase());
    if (!exists) {
      lastCol += 1;
      sh.getRange(1, lastCol).setValue(name);
      headers.push(name);
    }
  });
  const map = {};
  REQUEST_HEADERS.forEach(name => {
    map[name] = headers.findIndex(h => String(h || '').trim().toLowerCase() === name.toLowerCase());
  });
  return map;
}

function readEmployees_(activeOnly) {
  const sh = employeesSheet_();
  const last = sh.getLastRow();
  if (last < 2) return [];
  const headers = sh.getRange(1, 1, 1, sh.getLastColumn()).getDisplayValues()[0].map(h => String(h).toLowerCase().trim());
  const rows = sh.getRange(2, 1, last - 1, sh.getLastColumn()).getDisplayValues();
  return rows.map(r => {
    const getVal = (names) => { for (let n of names) { const idx = headers.indexOf(n); if (idx >= 0) return r[idx]; } return ''; };
    const activeText = String(getVal(['active', 'نشط'])).trim().toLowerCase();
    return {
      id: str_(getVal(['id'])), name: str_(getVal(['name', 'الاسم'])),
      jobTitle: str_(getVal(['jobtitle', 'المسمى'])), employeeId: str_(getVal(['employeeid', 'الرقم الوظيفي'])),
      nationality: str_(getVal(['nationality', 'الجنسية'])), personalId: str_(getVal(['personalid', 'الرقم الشخصي'])),
      phone: str_(getVal(['phone', 'الهاتف'])), email: str_(getVal(['email', 'البريد'])),
      balance: Number(getVal(['balance', 'الرصيد'])) || 600,
      active: !(activeText === 'false' || activeText === '0' || activeText === 'موقوف')
    };
  }).filter(e => e.name && e.employeeId && (!activeOnly || e.active));
}

function requestsAsObjects_() {
  const sh = requestsSheet_();
  const last = sh.getLastRow();
  if (last < 2) return [];
  const map = requestColumnMap_(sh);
  const lastCol = sh.getLastColumn();
  const values = sh.getRange(2, 1, last - 1, lastCol).getValues();
  const displayValues = sh.getRange(2, 1, last - 1, lastCol).getDisplayValues();
  return values.map((row, i) => {
    const data = {};
    REQUEST_HEADERS.forEach(k => { data[k] = row[map[k]]; });
    if (map.exitTime !== undefined) data.exitTime = displayValues[i][map.exitTime];
    if (map.returnTime !== undefined) data.returnTime = displayValues[i][map.returnTime];
    // Keep the saved decision statuses from the sheet. Rebuild only when the
    // field is genuinely empty; accept either JSON text or an already parsed array.
    if (Array.isArray(data.substituteApprovals)) {
      // already normalized
    } else if (data.substituteApprovals) {
      try {
        const parsed = JSON.parse(String(data.substituteApprovals));
        data.substituteApprovals = Array.isArray(parsed) ? parsed : [];
      } catch (_) { data.substituteApprovals = []; }
    }
    if (!Array.isArray(data.substituteApprovals) || data.substituteApprovals.length === 0) {
      data.substituteApprovals = getSubstituteApprovals_(data);
    }
    return { rowNumber: i + 2, data };
  });
}

function requireEmployeeAdminKey_(provided) {
  const expected = getProp_(PROP_STAFF_EDIT);
  if (!expected) throw new Error('مفتاح إدارة الموظفين غير مضبوط في Script Properties.');
  if (!provided || String(provided).trim() !== expected) throw new Error('مفتاح إدارة الموظفين غير صحيح.');
}

function addEmployee_(payload) {
  const sh = employeesSheet_();
  const row = [Utilities.getUuid(), payload.name, payload.jobTitle, payload.employeeId, payload.nationality, payload.personalId, payload.phone, payload.email, payload.balance || 600, true, new Date()];
  sh.appendRow(row);
  return json_({ success: true, message: 'تمت إضافة الموظف.' });
}
function updateEmployee_(payload) {
  const sh = employeesSheet_();
  const map = employeeColumnMap_(sh);
  const last = sh.getLastRow();
  const rows = sh.getRange(2, 1, last - 1, sh.getLastColumn()).getValues();
  for (let i = 0; i < rows.length; i++) {
    if (str_(rows[i][map.id]) === str_(payload.id)) {
      rows[i][map.name] = payload.name;
      rows[i][map.jobTitle] = payload.jobTitle;
      rows[i][map.employeeId] = payload.employeeId;
      rows[i][map.nationality] = payload.nationality;
      rows[i][map.personalId] = payload.personalId;
      rows[i][map.phone] = payload.phone;
      rows[i][map.email] = payload.email;
      rows[i][map.balance] = payload.balance || 600;
      rows[i][map.updatedAt] = new Date();
      sh.getRange(i + 2, 1, 1, rows[i].length).setValues([rows[i]]);
      return json_({ success: true, message: 'تم التحديث.' });
    }
  }
  throw new Error('لم يتم العثور على الموظف.');
}
function disableEmployee_(payload) {
  const sh = employeesSheet_();
  const map = employeeColumnMap_(sh);
  const last = sh.getLastRow();
  const rows = sh.getRange(2, 1, last - 1, sh.getLastColumn()).getDisplayValues();
  for (let i = 0; i < rows.length; i++) {
    if (str_(rows[i][map.id]) === str_(payload.id)) {
      sh.getRange(i + 2, map.active + 1).setValue(false);
      return json_({ success: true, message: 'تم إيقاف الحساب.' });
    }
  }
  throw new Error('لم يتم العثور على الموظف.');
}
function employeeColumnMap_(sh) {
  const headers = sh.getRange(1, 1, 1, sh.getLastColumn()).getDisplayValues()[0].map(h => String(h).toLowerCase().trim());
  const map = {};
  EMPLOYEE_HEADERS.forEach((name, i) => {
    const idx = headers.findIndex(h => String(h).trim().toLowerCase() === name.toLowerCase());
    map[name] = idx >= 0 ? idx : i;
  });
  return map;
}

function getRequestById_(id) {
  const item = requestsAsObjects_().find(x => x.data.requestId === str_(id));
  return item ? json_({ success: true, data: item.data }) : json_({ success: false, message: 'غير موجود' });
}
function getAllRequests_() { return json_({ success: true, requests: requestsAsObjects_().map(x => x.data).reverse() }); }
function getAdminStats_() {
  const allReqs = requestsAsObjects_();
  let total = allReqs.length, academic = 0, admin = 0;
  allReqs.forEach(item => {
    const d = item.data;
    const isAdmin = String(d.coverageType || '') === 'إداري' || String(d.subject || '') === 'كادر إداري';
    if (isAdmin) admin++; else academic++;
  });
  return json_({ success: true, total, academic, admin });
}