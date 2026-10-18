<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||$argc!==2)exit("Usage: php tools/make-admin.php EMAIL\n");
$db=new PDO('sqlite:'.dirname(__DIR__).'/var/blink.sqlite');
$q=$db->prepare('UPDATE users SET is_admin=1 WHERE email=?');$q->execute([$argv[1]]);
if($q->rowCount()!==1){fwrite(STDERR,"No matching account. Register first.\n");exit(1);}
echo "Administrator granted.\n";
