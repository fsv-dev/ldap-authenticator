<?php

require __DIR__ . '/../bootstrap.php';

use Tester\Assert;

class DatabaseManager extends Tester\TestCase
{
	private $db;

	public function __construct()
	{
		$this->db = Mockery::mock(\Nette\Database\Context::class);
	}

	public function testTableDetect()
	{
		$databaseManager = new \Ldap\DatabaseManager($this->db);

		$db = $this->db->shouldReceive('query->fetch')->times(2)->andReturn(['array'], FALSE);

		Assert::true($databaseManager->tableDetect($db));
		Assert::false($databaseManager->tableDetect($db));
	}
}

$testCase = new DatabaseManager();
$testCase->run();