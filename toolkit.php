<?php
// toolkit.php
// Web Security Assessment Toolkit
// Portfolio Edition

function ensure_scheme($url) {
    if (stripos($url, 'http') !== 0) return 'https://' . $url;
    return $url;
}

function get_headers_safe($url) {
    $url = ensure_scheme($url);
    $opts = array(
        'http' => array('method' => "GET", 'header' => "User-Agent: Test/3.0\r\n", 'timeout' => 10),
        'ssl' => array('verify_peer' => false, 'verify_peer_name' => false)
    );
    $context = stream_context_create($opts);
    $h = @get_headers($url, 1, $context);
    return $h ?: false;
}

function parse_security_headers($headers) {
    $result = [
        'has_hsts' => false, 'hsts_value' => '',
        'has_csp' => false, 'csp_value' => '',
        'x_frame_options' => '', 'x_content_type_options' => '',
        'referrer_policy' => '', 'permissions_policy' => '', 'server_banner' => '',
        'all_headers' => []
    ];
    if (!is_array($headers)) return $result;
    foreach ($headers as $k => $v) {
        $lk = strtolower($k);
        $val = is_array($v) ? implode(", ", $v) : $v;
        $result['all_headers'][$k] = $val;
        if ($lk === 'strict-transport-security') { $result['has_hsts'] = true; $result['hsts_value'] = $val; }
        elseif ($lk === 'content-security-policy') { $result['has_csp'] = true; $result['csp_value'] = $val; }
        elseif ($lk === 'x-frame-options') { $result['x_frame_options'] = $val; }
        elseif ($lk === 'x-content-type-options') { $result['x_content_type_options'] = $val; }
        elseif ($lk === 'referrer-policy') { $result['referrer_policy'] = $val; }
        elseif ($lk === 'permissions-policy' || $lk === 'feature-policy') { $result['permissions_policy'] = $val; }
        elseif ($lk === 'server') { $result['server_banner'] = $val; }
    }
    return $result;
}

function get_recommendation_icon_text($status, $text) {
    if ($status === 'pass') return "✔ $text";
    if ($status === 'warn') return "⚠ $text";
    return "✗ $text";
}

function get_set_cookie_flags($headers) {
    $cookies = [];
    if (!is_array($headers)) return $cookies;
    if (isset($headers['Set-Cookie'])) {
        $vals = $headers['Set-Cookie'];
        if (!is_array($vals)) $vals = [$vals];
        foreach ($vals as $c) $cookies[] = $c;
    }
    return $cookies;
}

function check_common_paths($target, $paths = []) {
    $found = [];
    $base = ensure_scheme($target);
    $base_no_path = preg_replace('#/.*#', '', $base);
    foreach ($paths as $p) {
        $url = rtrim($base_no_path, '/') . '/' . ltrim($p, '/');
        $h = @get_headers($url, 1);
        if ($h !== false && isset($h[0])) {
            preg_match('/HTTP\/\d+\.\d+\s+(\d+)/', $h[0], $m);
            $code = isset($m[1]) ? intval($m[1]) : 0;
            if ($code < 400) $found[$p] = $code;
        }
    }
    return $found;
}
function check_upload_dirs($target) { return check_common_paths($target, ['uploads','/uploads/','/files/','upload','/uploads/index.php']); }
function check_sensitive_dirs($target) { return check_common_paths($target, ['config','/config.php','backup','/backup/','.git','/admin/']); }
function check_login_pages($target) { return check_common_paths($target, ['login','/login','/admin/login','/administrator','/wp-login.php','/user/login','/admin','/signin','/account/login']); }

function get_domain_ip($domain) {
    $d = preg_replace('#https?://#i', '', $domain);
    $d = preg_replace('#/.*#', '', $d);
    $ip = gethostbyname($d);
    return $ip ? $ip : ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
}

function dnsbl_and_spamhaus_check($domain) {
    $d = preg_replace('#https?://#i', '', $domain);
    $d = preg_replace('#/.*#', '', $d);
    $ip = gethostbyname($d);
    if (!$ip || $ip === $d) {
        return ['ip' => '', 'dnsbl_listed' => [], 'spamhaus_listed' => false];
    }

    $rev = implode('.', array_reverse(explode('.', $ip)));
  
    $dnsbls = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org"
    ];

    $listed = [];
    foreach ($dnsbls as $dnsbl) {
        $q = $rev . '.' . $dnsbl . '.';
        if (@checkdnsrr($q, 'A')) $listed[] = $dnsbl;
    }

    $spamhaus_q = $rev . '.zen.spamhaus.org.';
    $spamhaus_listed = @checkdnsrr($spamhaus_q, 'A');

    return ['ip' => $ip, 'dnsbl_listed' => $listed, 'spamhaus_listed' => $spamhaus_listed];
}

$target = '';
$report = null;
$error = '';
$ip = '';
$phase2 = [];
$dnsbl_result = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['target'])) {
    $target = trim($_POST['target']);
    if (strlen($target) > 300) $error = "Input too long.";
    else {
        $headers = get_headers_safe($target);
        if (!$headers) $error = "Unable to retrieve website headers. Please verify the URL or ensure the website is publicly accessible.Target may be offline or blocked by server (or outbound requests disabled).";
        else {
            $report = parse_security_headers($headers);
            $ip = get_domain_ip($target);

            $dnsbl_result = dnsbl_and_spamhaus_check($target);

            $uploads = check_upload_dirs($target);
            $phase2[] = [
                'check' => 'File Upload Directory Exposure',
                'value' => !empty($uploads) ? implode(', ', array_keys($uploads)) : 'Not Provided by Server',
                'rec'   => !empty($uploads) ? 'Potential upload dirs accessible' : 'No common upload path detected',
                'status'=> !empty($uploads) ? 'warn' : 'pass'
            ];

            $cookies = get_set_cookie_flags($headers);
            if (empty($cookies)) {
                $phase2[] = ['check'=>'CSRF / Cookie Flags','value'=>'Not Provided by Server','rec'=>'No session cookies detected','status'=>'warn'];
            } else {
                $flagSummary = []; $flagIssues = [];
                foreach($cookies as $c){
                    $flags = [];
                    if (stripos($c,'httponly') !== false) $flags[] = 'HttpOnly';
                    if (stripos($c,'secure') !== false) $flags[] = 'Secure';
                    if (stripos($c,'samesite') !== false) $flags[] = 'SameSite';
                    $flagSummary[] = count($flags) ? implode('|', $flags) : 'none';
                    if (!in_array('HttpOnly', $flags)) $flagIssues[] = 'Missing HttpOnly';
                    if (!in_array('Secure', $flags)) $flagIssues[] = 'Missing Secure';
                }
                $phase2[] = ['check'=>'CSRF / Cookie Flags','value'=>implode('; ',$flagSummary),'rec'=>!empty($flagIssues)?implode('; ',$flagIssues):'Cookie flags look good','status'=>!empty($flagIssues)?'warn':'pass'];
            }

            $sdirs = check_sensitive_dirs($target);
            $phase2[] = ['check'=>'Sensitive Directory Exposure','value'=>!empty($sdirs)?implode(', ',array_keys($sdirs)):'Not Provided by Server','rec'=>!empty($sdirs)?'Sensitive dirs found':'No sensitive dirs detected','status'=>!empty($sdirs)?'warn':'pass'];

            $logins = check_login_pages($target);
            $sessionCookie = false;
            foreach($cookies as $c) if (stripos($c,'phpsessid')!==false || stripos($c,'session')!==false) $sessionCookie = true;
            $phase2[] = ['check'=>'Authentication / Session Indicators','value'=>!empty($logins)?implode(', ',array_keys($logins)):'Not Provided by Server','rec'=>$sessionCookie?'Session cookies present. Ensure secure flags':'No session cookies detected','status'=>$sessionCookie?'warn':'pass'];

            $phase2[] = [
                'check' => 'DNSBL / RBL Blacklist Status',
                'value' => !empty($dnsbl_result['dnsbl_listed']) ? implode(', ', $dnsbl_result['dnsbl_listed']) : 'Not listed on major DNSBL',
                'rec'   => !empty($dnsbl_result['dnsbl_listed']) ? 'Listed in DNSBL - investigate (Spamhaus, etc.)' : 'No DNSBL listing found',
                'status'=> !empty($dnsbl_result['dnsbl_listed']) ? 'warn' : 'pass'
            ];

            $phase2[] = [
                'check' => 'Spamhaus (zen.spamhaus.org)',
                'value' => $dnsbl_result['spamhaus_listed'] ? 'Listed' : 'Not Listed',
                'rec'   => $dnsbl_result['spamhaus_listed'] ? 'Listed on Spamhaus - investigate immediately' : 'Not listed on Spamhaus',
                'status'=> $dnsbl_result['spamhaus_listed'] ? 'warn' : 'pass'
            ];
        }
    }
}

if (isset($_GET['download']) && $_GET['download'] === 'csv' && isset($_GET['target'])) {
    $t = $_GET['target'];
    header('Content-Type: text/csv');
    $safeFile = preg_replace('/[^a-z0-9_-]/i','_',$t);
    header('Content-Disposition: attachment; filename="web_security_assessment_'.$safeFile.'.csv"');
    $out = fopen('php://output','w');

    fputcsv($out, ['Category','Item','Value','Recommendation / Status']);

    $headers_csv = get_headers_safe($t);
    $report_csv = $headers_csv ? parse_security_headers($headers_csv) : null;

    if ($report_csv) {
        foreach($report_csv['all_headers'] as $k=>$v) {
            fputcsv($out, ['Security Header', $k, $v ? $v : 'Not Provided by Server', '']);
        }

        $uploads_csv = check_upload_dirs($t);
        $cookies_csv = get_set_cookie_flags($headers_csv);

        if (empty($cookies_csv)) {
            fputcsv($out, ['Phase2','CSRF / Cookie Flags','Not Provided by Server','No session cookies detected']);
        } else {
            $flagSummary=[]; $flagIssues=[];
            foreach($cookies_csv as $c){
                $flags=[]; if(stripos($c,'httponly')!==false) $flags[]='HttpOnly';
                if(stripos($c,'secure')!==false) $flags[]='Secure';
                if(stripos($c,'samesite')!==false) $flags[]='SameSite';
                $flagSummary[] = count($flags)?implode('|',$flags):'none';
                if(!in_array('HttpOnly',$flags)) $flagIssues[]='Missing HttpOnly';
                if(!in_array('Secure',$flags)) $flagIssues[]='Missing Secure';
            }
            fputcsv($out,['Phase2','CSRF / Cookie Flags',implode('; ',$flagSummary),!empty($flagIssues)?implode('; ',$flagIssues):'Cookie flags look good']);
        }

        fputcsv($out,['Phase2','File Upload Directory Exposure', !empty($uploads_csv)?implode(', ',array_keys($uploads_csv)):'Not Provided by Server', !empty($uploads_csv)?'Potential upload dirs accessible':'No common upload path detected']);

        $sdirs_csv = check_sensitive_dirs($t);
        fputcsv($out,['Phase2','Sensitive Directory Exposure', !empty($sdirs_csv)?implode(', ',array_keys($sdirs_csv)):'Not Provided by Server', !empty($sdirs_csv)?'Sensitive dirs found':'No sensitive dirs detected']);

        $logins_csv = check_login_pages($t);
        fputcsv($out,['Phase2','Authentication / Session Indicators', !empty($logins_csv)?implode(', ',array_keys($logins_csv)):'Not Provided by Server', '']);

        $dnsbl_csv = dnsbl_and_spamhaus_check($t);
        fputcsv($out,['Phase2','DNSBL / RBL IP', $dnsbl_csv['ip'] ? $dnsbl_csv['ip'] : '','']);
        fputcsv($out,['Phase2','DNSBL / RBL Listed', !empty($dnsbl_csv['dnsbl_listed'])?implode(', ',$dnsbl_csv['dnsbl_listed']):'Not listed on major DNSBL', !empty($dnsbl_csv['dnsbl_listed'])?'Listed':'Not Listed']);
        fputcsv($out,['Phase2','Spamhaus (zen.spamhaus.org)', $dnsbl_csv['spamhaus_listed'] ? 'Listed' : 'Not Listed', $dnsbl_csv['spamhaus_listed'] ? 'Listed' : 'Not Listed']);

        fputcsv($out,['Network','IP Address', get_domain_ip($t), '']);

        fputcsv($out, ['Meta','Entered Website', $t, '']);
    }

    fclose($out);
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Web Security Assessment Toolkit</title>
  <link rel="stylesheet" href="creative.css">
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body>

  <header class="site-header">
    <div class="header-inner">
      <div class="header-left">
        <div class="line1"><strong>Web Security Assessment Toolkit</strong></div>
        <div class="line2">Security Header Analysis • Vulnerability Assessment • DNSBL Intelligence</div>
      </div>
      <div class="header-right">
       <div class="line1">PHP • HTML • CSS • HTTP Security Analysis</strong></div>
      </div>
    </div>
  </header>

  <nav class="menu-bar">
    <div class="menu-inner">
        <a href="toolkit.php" class="active">Toolkit</a>
    </div>
  </nav>

  <main class="page-wrapper">
    <section class="card">
      <h3 style="color:#c62828;margin:0 0 8px 0;">Web Security Assessment Toolkit</h3>
      <p style="margin:0 0 14px 0;color:#444">Analyze website security headers, identify common web security misconfigurations, perform DNSBL reputation checks, and generate downloadable security assessment reports.</p>

      <form class="Toolkit-form" method="post" action="toolkit.php">
        <input type="text" name="target" placeholder="example.com or https://example.com" value="<?php echo htmlentities($target); ?>" required>
        <button type="submit" class="btn-primary">Run Assessment</button>
        <?php if ($report): ?>
          <a class="csv-link" href="?download=csv&target=<?php echo urlencode($target); ?>">Export Report</a>
        <?php endif; ?>
      </form>

      <?php if ($error): ?>
        <div style="color:#b00020;margin-top:12px;"><?php echo htmlentities($error); ?></div>
      <?php endif; ?>

      <?php if ($report): ?>

        <h3 style="margin-top:18px;">Security Assessment Summary</h3>
        <table class="table">
          <tr><th>Header</th><th>Value</th><th>Recommendation</th></tr>
          <tr><td>HSTS</td><td><?php echo $report['has_hsts'] ? htmlentities($report['hsts_value']) : 'Not Provided by Server'; ?></td><td><?php echo htmlentities(get_recommendation_icon_text($report['has_hsts'] ? 'pass' : 'fail','HSTS')); ?></td></tr>
          <tr><td>Content-Security-Policy</td><td><?php echo $report['has_csp'] ? htmlentities($report['csp_value']) : 'Not Provided by Server'; ?></td><td><?php echo htmlentities(get_recommendation_icon_text($report['has_csp'] ? 'pass' : 'fail','CSP')); ?></td></tr>
          <tr><td>X-Frame-Options</td><td><?php echo $report['x_frame_options'] ? htmlentities($report['x_frame_options']) : 'Not Provided by Server'; ?></td><td><?php echo htmlentities(get_recommendation_icon_text($report['x_frame_options'] ? 'pass' : 'fail','X-Frame-Options')); ?></td></tr>
          <tr><td>X-Content-Type-Options</td><td><?php echo $report['x_content_type_options'] ? htmlentities($report['x_content_type_options']) : 'Not Provided by Server'; ?></td><td><?php echo htmlentities(get_recommendation_icon_text($report['x_content_type_options'] ? 'pass' : 'fail','X-Content-Type-Options')); ?></td></tr>
          <tr><td>Referrer-Policy</td><td><?php echo $report['referrer_policy'] ? htmlentities($report['referrer_policy']) : 'Not Provided by Server'; ?></td><td><?php echo htmlentities(get_recommendation_icon_text($report['referrer_policy'] ? 'pass' : 'warn','Referrer-Policy')); ?></td></tr>
          <tr><td>Permissions/Feature Policy</td><td><?php echo $report['permissions_policy'] ? htmlentities($report['permissions_policy']) : 'Not Provided by Server'; ?></td><td><?php echo htmlentities(get_recommendation_icon_text($report['permissions_policy'] ? 'pass' : 'warn','Permissions Policy')); ?></td></tr>
          <tr><td>Server Banner</td><td><?php echo $report['server_banner'] ? htmlentities($report['server_banner']) : 'Not Provided by Server'; ?></td><td><?php echo htmlentities(get_recommendation_icon_text($report['server_banner'] ? 'warn' : 'pass','Server Banner')); ?></td></tr>
        </table>

        <h3 style="margin-top:18px;">Security Assessment Results</h3>
        <table class="table">
          <tr><th>Assessment Check</th><th>Value</th><th>Recommendation / Status</th></tr>
          <?php foreach($phase2 as $row): ?>
            <tr>
              <td><?php echo htmlentities($row['check']); ?></td>
              <td><?php echo htmlentities($row['value']); ?></td>
              <td><?php echo htmlentities(get_recommendation_icon_text($row['status'],$row['rec'])); ?></td>
            </tr>
          <?php endforeach; ?>
          <tr><td>IP Address</td><td><?php echo htmlentities($ip); ?></td><td>Not Applicable</td></tr>
        </table>

        <h3 style="margin-top:18px;">HTTP Response Headers (raw)</h3>
        <pre style="background:#fafafa;padding:12px;border:1px solid #eee;border-radius:4px;"><?php
          foreach($report['all_headers'] as $k=>$v){
            echo htmlentities($k.': '.($v?$v:'Not Provided by Server'))."\n";
          }
        ?></pre>

      <?php endif; ?>

    </section>
  </main>
<footer class="site-footer">

<div class="footer-inner">

<div class="footer-left">

<strong>Web Security Assessment Toolkit</strong>

<div>
Portfolio Edition
</div>

</div>

<div class="footer-right">

<strong>Technology Stack</strong>

<div>
PHP • HTML • CSS • HTTP Security Analysis
</div>

</div>

</div>

</footer>
 
</body>
</html>
