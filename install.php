<?php
declare(strict_types=1);
foreach(['pdo_sqlite','mbstring'] as $e)if(!extension_loaded($e)){fwrite(STDERR,"Missing extension: $e\n");exit(1);}
@mkdir(__DIR__.'/var/sessions',0700,true);
$db=new PDO('sqlite:'.__DIR__.'/var/blink.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
echo "Ready. Run php -S localhost:8000 -t public router.php. Schema is initialized on first request. Register your account; use php tools/make-admin.php EMAIL to grant moderation.\n";
