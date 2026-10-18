<?php
if (in_array($path, ['/legal','/privacy','/terms'], true)) {
 page_start('Instance policies','Self-hosted Blink policies.');
 echo '<section class="shell narrow request-page"><h1>Self-hosted Blink</h1><p>This open-source installation is operated independently. Accounts are for adults aged 18 or older. Posts and comments are public; account email and password hashes are private. No bundled analytics or author feedback integration is enabled.</p><p>Share only content you may publish. Use Account settings to delete your account and its posts/comments. Backups, mail delivery and server log retention are controlled by the operator. The operator must supply contact details and deployment-specific terms before public hosting. Software is provided as-is under the MIT license.</p></section>';
 page_end();exit;
}
if($path==='/account') {
 $user=require_user();$error='';
 if($method==='POST'){verify_csrf();$q=db()->prepare('SELECT password_hash FROM users WHERE id=?');$q->execute([$user['id']]);$hash=$q->fetchColumn();if(!rate_limit('delete-account-'.$user['id'],5,3600))$error='Too many attempts. Try again later.';elseif(!password_verify((string)($_POST['password']??''),$hash))$error='Your password did not match.';elseif(($_POST['confirm']??'')!=='DELETE')$error='Type DELETE to confirm.';else{db()->prepare('DELETE FROM users WHERE id=?')->execute([$user['id']]);$_SESSION=[];session_regenerate_id(true);flash('success','Your account and its content have been deleted.');redirect('');}}
 page_start('Account settings','Manage your Blink account.','','noindex, nofollow');echo '<section class="shell narrow request-page"><h1>Account settings</h1><p>Signed in as @'.e($user['username']).'.</p><h2>Delete your account</h2><p>This permanently removes your account, all your blinks, comments and category requests. Discussions on your blinks are also deleted. This cannot be undone.</p>';
 if($error)echo '<div class="form-errors">'.e($error).'</div>';
 echo '<form method="post" class="stack-form" data-confirm="Permanently delete your account and all its content?"><input type="hidden" name="csrf" value="'.csrf().'"><label>Current password<input type="password" name="password" required autocomplete="current-password"></label><label>Type DELETE to confirm<input name="confirm" required pattern="DELETE"></label><button class="button button-soft">Permanently delete account</button></form></section>';page_end();exit;
}
if($path==='/admin/requests') {
 $user=require_user();if(!is_admin($user))render_error('Not available','This page is for the site owner.',403);
 if($method==='POST'){verify_csrf();$id=(int)($_POST['id']??0);$status=(string)($_POST['status']??'');if(in_array($status,['reviewed','declined'],true)){db()->prepare('UPDATE category_requests SET status=? WHERE id=?')->execute([$status,$id]);flash('success','Request status updated. Category additions are reviewed and released separately.');}redirect('admin/requests');}
 page_start('Category request inbox','Review category requests.','','noindex, nofollow');echo '<section class="shell narrow request-page"><h1>Category requests</h1><p>Review suggestions here. Marking a request reviewed does not publish a new category.</p>';
 $rows=db()->query('SELECT r.*,u.username FROM category_requests r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 100')->fetchAll();if(!$rows)echo '<p>No requests yet.</p>';
 foreach($rows as $r){echo '<article class="change-entry"><h2>'.e($r['name']).'</h2><p>'.e($r['reason']).'</p><p>@'.e($r['username']).' · '.e($r['created_at']).' · '.e($r['status']).'</p><form method="post" class="inline-actions"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="id" value="'.$r['id'].'"><button class="button button-soft" name="status" value="reviewed">Mark reviewed</button><button class="button button-soft" name="status" value="declined">Decline</button></form></article>';}
 echo '</section>';page_end();exit;
}
