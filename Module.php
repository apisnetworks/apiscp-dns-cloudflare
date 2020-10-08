<?php declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, August 2018
	 */

	namespace Opcenter\Dns\Providers\Cloudflare;

	use Cloudflare\API\Endpoints\API;
	use Cloudflare\API\Endpoints\DNS;
	use Cloudflare\API\Endpoints\Zones;
	use Opcenter\Dns\Record as RecordBase;
	use GuzzleHttp\Exception\ClientException;
	use Module\Provider\Contracts\ProviderInterface;
	use Opcenter\Net\IpCommon;

	class Module extends \Dns_Module implements ProviderInterface
	{
		/**
		 * apex markers are marked with @
		 */
		protected const HAS_ORIGIN_MARKER = true;
		public const DNS_TTL = 1800;

		// @var int minimum TTL
		public const DNS_TTL_MIN = 120;

		use \NamespaceUtilitiesTrait;
		// @var array API credentials
		protected static $permitted_records = [
			'A',
			'AAAA',
			'CAA',
			'CERT',
			'CNAME',
			'DNSKEY',
			'DS',
			'LOC',
			'MX',
			'NAPTR',
			'NS',
			'PTR',
			'SMIMEA',
			'SRV',
			'SPF',
			'SSHFP',
			'TLSA',
			'TXT',
			'URI',
		];

		private $key;
		//@var int DNS_TTL
		private $metaCache = [];

		public function __construct()
		{
			parent::__construct();
			// two pathways to evaluating a key, either [dns] => key or auth.yaml
			// [dns] => provider_key is set on creation unless... it's admin
			$this->key = $this->getAuthenticationSettings();
			if (null === $this->key || is_scalar($this->key)) {
				// auth bearer
				$this->key = [
					'key'   => (string)$this->key
				];
			}

			$this->key += ['email' => null, 'key' => null];

			if (!isset($this->key['proxy'])) {
				$this->key['proxy'] = false;
			} else if (\is_string($this->key['proxy'])) {
				$this->key['proxy'] = $this->key['proxy'] === 'true';
			} else {
				$this->key['proxy'] = (bool)$this->key['proxy'];
			}

			$this->key['jumpstart'] = (bool)($this->key['jumpstart'] ?? false);
		}

		/**
		 * Fetch authentication from site metadata, config.ini, or auth.yaml
		 *
		 * @return array|null|string
		 */
		private function getAuthenticationSettings()
		{
			if (null !== ($key = $this->getServiceValue('dns','key'))) {
				return $key;
			}

			if (!\defined('AUTH_CLOUDFLARE_KEY') || empty(AUTH_CLOUDFLARE_KEY)) {
				return DNS_PROVIDER_KEY;
			}

			$params = [
				'key' => AUTH_CLOUDFLARE_KEY
			];

			foreach (['proxy', 'jumpstart', 'email'] as $var) {
				$ucvar = strtoupper($var);
				if (!\defined("AUTH_CLOUDFLARE_${ucvar}")) {
					continue;
				}
				$params[$var] = \constant("AUTH_CLOUDFLARE_${ucvar}");
			}

			return $params;
		}

		/**
		 * Add a DNS record
		 *
		 * @param string $zone
		 * @param string $subdomain
		 * @param string $rr
		 * @param string $param
		 * @param int    $ttl
		 * @return bool
		 */
		public function add_record(
			string $zone,
			string $subdomain,
			string $rr,
			string $param,
			int $ttl = self::DNS_TTL
		): bool {
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			/**
			 * @var DNS $api
			 */
			$api = $this->makeApi(DNS::class);
			$record = new Record($zone, [
				'name'      => $subdomain,
				'rr'        => $rr,
				'parameter' => $param,
				'ttl'       => $ttl
			]);

			try {
				$cfu = clone $record;
				/**
				 * Spreading is a bit nuanced. We want expansion with record updates to
				 * coerce types if necessary, but addRecord expects "data" to be broken out.
				 */
				$data = $cfu->spreadParameters();
				/** @var $api API */
				$ret = $api->addRecord(
					$this->getZoneId($zone),
					$cfu['rr'],
					$cfu['name'],
					(string)$cfu['parameter'],
					$cfu['ttl'],
					$this->isProxiable($cfu['rr'], (string)$cfu['parameter']),
					(string)($cfu->getMeta('priority') ?? ''),
					$data['data'] ?? []
				);
				if ($ret) {
					$this->addCache($record->setMeta('id', $api->getBody()->result->id));
				}
			} catch (ClientException $e) {
				$error = json_decode($e->getResponse()->getBody()->getContents(), true);
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Failed to create record `%s' type %s: %s",
					$fqdn,
					$rr,
					array_get($error, 'errors.0.error_chain.0.message', array_get($error, 'errors.0.message'))
				);
			}

			return $ret;
		}

		/**
		 * Record may be proxied in CF
		 *
		 * @param string $rr
		 * @return bool
		 */
		private function isProxiable(string $rr, string $param = ''): bool
		{
			if (!$this->key['proxy']) {
				return false;
			}

			if ($rr === 'CNAME') {
				return true;
			}

			if ($rr !== 'AAAA' && $rr !== 'A') {
				return false;
			}

			// CF cannot proxy internal/reserved addresses
			return !IpCommon::reserved($param);
		}

		/**
		 * Verify record exists
		 *
		 * CloudFlare handles a boutique of resource records not available in PHP
		 *
		 * @param string      $zone
		 * @param string      $subdomain
		 * @param string      $rr
		 * @param string|null $parameter
		 * @return bool
		 */
		public function record_exists(
			string $zone,
			string $subdomain,
			string $rr = 'ANY',
			string $parameter = ''
		): bool {
			$parameter = (string)$parameter;
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $parameter)) {
				return false;
			}
			$args = [
				'name'      => $subdomain,
				'rr'        => $rr,
			];
			if ($parameter !== '') {
				$args['parameter'] = $parameter;
			}
			$record = new Record($zone, $args);

			return (bool)$this->getRecordId($record);
		}


		/**
		 * Remove a DNS record
		 *
		 * @param string      $zone
		 * @param string      $subdomain
		 * @param string      $rr
		 * @param string      $param
		 * @return bool
		 */
		public function remove_record(string $zone, string $subdomain, string $rr, string $param = ''): bool
		{
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param)) {
				return false;
			}
			$api = $this->makeApi(DNS::class);
			$record = new Record($zone, ['name' => $subdomain, 'rr' => $rr, 'parameter' => $param]);
			$id = $this->getRecordId($record);

			if (!$id) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');
				return error("Record `%s' (rr: `%s', param: `%s')  does not exist", $fqdn, $rr, $param);
			}

			try {
				$ret = $api->deleteRecord($this->getZoneId($zone), $id);
				$this->removeCache($record);
				return $ret;
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');
				return error("Failed to delete record `%s' type %s", $fqdn, $rr);
			}

			return false;
		}

		/**
		 * Add DNS zone to service
		 *
		 * @param string $domain
		 * @param string $ip
		 * @return bool
		 */
		public function add_zone_backend(string $domain, string $ip): bool
		{
			$api = $this->makeApi(Zones::class);
			try {
				$api->addZone($domain, $this->key['jumpstart'] ?? false);
			} catch (ClientException $e) {
				if (false !== strpos($e->getMessage(), '1061,')) {
					return info("Zone `%s' present in Cloudflare - not overwriting", $domain);
				}

				return error("Failed to add zone `%s', error: %s", $domain, $e->getMessage());
			}

			return true;
		}

		/**
		 * Remove DNS zone from nameserver
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function remove_zone_backend(string $domain): bool
		{
			$client = $this->makeApi(Zones::class);
			$id = $this->getZoneId($domain);
			try {
				$client->deleteZone($id);
				unset($this->zoneCache[$domain]);
			} catch (ClientException $e) {
				return error("Failed to delete zone `%s', error: %s", $domain, $e->getMessage());
			}

			return true;
		}

		/**
		 * Get raw zone data
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function zoneAxfr(string $domain): ?string
		{
			$client = $this->makeApi(DNS::class);
			$ns = $this->get_hosting_nameservers($domain);
			$soa = array_get($this->get_records_external('', 'soa', $domain, $ns),
				0, []);
			if (!$ns) {
				return null;
			}
			$ttldef = (int)array_get(preg_split('/\s+/', $soa['parameter'] ?? ''), 6, static::DNS_TTL);
			$preamble = [
				"${domain}.\t${ttldef}\tIN\tSOA\t${soa['parameter']}",
			];
			foreach ($this->get_hosting_nameservers($domain) as $ns) {
				$preamble[] = "${domain}.\t${ttldef}\tIN\tNS\t${ns}.";
			}
			try {
				$id = $this->getZoneId($domain);
				if (null === $id) {
					if (is_debug()) {
						var_dump($this->zoneCache, $this->populateZoneMetaCache(), $this->zoneCache);
						$api2 = $this->makeApi(Zones::class);
						var_dump($api2->listZones()->result);
					}
					error("Zone `%s' not properly provisioned", $domain);

					return null;
				}
				$page = 1;
				$records = [];
				do {
					$query = $client->listRecords($id, '', '', '', $page, 10);
					$records = array_merge($records, $query->result);
					$pagenr = data_get($query, 'result_info.total_pages');
				} while ($pagenr >= ++$page);
				// naked zone if $records === []
			} catch (ClientException $e) {
				error('Failed to transfer DNS records from CF - try again later');

				return null;
			}

			$this->zoneCache[$domain] = [];
			foreach ($records as $record) {
				$truncateLength = \strlen($record->zone_name);
				switch (strtoupper($record->type)) {
					case 'MX':
						$parameter = $record->priority . ' ' . $record->content;
						break;
					case 'URI':
						$parameter = $record->priority . ' ' . $record->data->weight . ' ' . $record->data->content;
						break;
					case 'SRV':
						$parameter = $record->priority . ' ' . $record->content;
						break;
					case 'TXT':
						$parameter = $record->content;
						break;
					default:
						$parameter = $record->content;
				}
				$key = rtrim(substr($record->name, 0, \strlen($record->name) - $truncateLength), '.');
				if ($key === '') {
					$key = '@';
				}

				$r = (new Record($domain,
					[
						'name'      => $key,
						'rr'        => $record->type,
						'ttl'       => $record->ttl,
						'parameter' => str_replace("\t", ' ', $parameter),
					]
				))->setMeta('id', $record->id);
				$this->addCache($r);
				$preamble[] = $record->name . ".\t" . $record->ttl . "\tIN\t" .
					$record->type . "\t" . $parameter;
			}

			return implode("\n", $preamble);
		}

		private function makeApi(string $abstract): API
		{
			return \Opcenter\Dns\Providers\Cloudflare\Api::api(
				$this->key['email'],
				$this->key['key'],
				$abstract
			);
		}

		/**
		 * Get hosting nameservers
		 *
		 * @param string|null $domain
		 * @return array
		 */
		public function get_hosting_nameservers(string $domain = null): array
		{
			if (!$domain) {
				error('Cloudflare DNS provider requires the $domain parameter');

				return [];
			}

			return $this->getZoneMeta($domain, 'name_servers') ?? [];
		}

		/**
		 * Get zone meta information
		 *
		 * @param string $domain
		 * @param string $key
		 * @return mixed|null
		 */
		private function getZoneMeta(string $domain, string $key)
		{
			if (!isset($this->metaCache[$domain])) {
				$this->populateZoneMetaCache();
			}

			return $this->metaCache[$domain][$key] ?? null;
		}

		protected function populateZoneMetaCache()
		{

			$api = $this->makeApi(Zones::class);
			/**
			 * @todo prime whole cache vs per-domain priming on larger accounts
			 */
			$raw = array_map(static function ($zone) {
				return (array)$zone;
			}, $api->listZones('', '', 1, 1000)->result);

			$this->metaCache = array_merge($this->metaCache, array_combine(array_column($raw, 'name'), $raw));
		}

		/**
		 * Get internal CF zone ID
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function getZoneId(string $domain): ?string
		{
			return $this->getZoneMeta($domain, 'id');
		}

		/**
		 * Modify a DNS record
		 *
		 * @param string $zone
		 * @param Record $old
		 * @param Record $new
		 * @return bool
		 */
		protected function atomicUpdate(string $zone, RecordBase $old, RecordBase $new): bool
		{
			// @var \Cloudflare\Api\Endpoints\DNS @api
			if (!$this->canonicalizeRecord($zone, $old['name'], $old['rr'], $old['parameter'], $old['ttl'])) {
				return false;
			}
			// ensure old TTL is always unset
			$old['ttl'] = null;
			if (!$this->getRecordId($old)) {
				return error("failed to find record ID in CF zone `%s' - does `%s' (rr: `%s', parameter: `%s') exist?",
					$zone, $old['name'], $old['rr'], $old['parameter']);
			}
			if (!$this->canonicalizeRecord($zone, $new['name'], $new['rr'], $new['parameter'], $new['ttl'])) {
				return false;
			}
			$api = $this->makeApi(DNS::class);
			try {
				$merged = clone $old;
				$new = $merged->merge($new);
				$cfu = clone $new;
				$data = $cfu->spreadParameters();
				$result = $api->updateRecordDetails($this->getZoneId($zone), $this->getRecordId($old), $data + [
					'type'    => $cfu['rr'],
					'name'    => $cfu['name'],
					'ttl'     => $cfu['ttl'] ?? null,
					'content' => $cfu['parameter'],
					'priority' => $data['data']['priority'] ?? null,
				]);
				$new->setMeta('id', $result->result->id ?? null);
			} catch (ClientException $e) {
				$reason = \json_decode($e->getResponse()->getBody()->getContents());
				return error("Failed to update record `%s' on zone `%s' (old - rr: `%s', param: `%s'; new - name: `%s' rr: `%s', param: `%s'): %s",
					$old['name'],
					$zone,
					$old['rr'],
					$old['parameter'], $new['name'] ?? $old['name'], $new['rr'], $new['parameter'] ?? $old['parameter'],
					$reason->errors[0]->error_chain[0]->message ?? $reason->errors[0]->message
				);
			}
			array_forget($this->zoneCache[$old->getZone()], $this->getCacheKey($old));
			$this->addCache($new);

			return true;
		}

		protected function canonicalizeRecord(
			string &$zone,
			string &$subdomain,
			string &$rr,
			string &$param,
			int &$ttl = null
		): bool {
			if (!parent::canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			if ($rr === 'MX') {
				$param = rtrim($param, '.');
			}
			if ($rr === 'TXT' && !preg_match('/^"[^"]*"$/', $param)) {
				$param = trim($param, '"');
			}
			// @TODO move to general canonicalization?
			if ($rr === 'CNAME') {
				$param = rtrim($param, '.');
			}
			if (!$ttl) {
				$ttl = self::DNS_TTL;
			} else if ($ttl < 1 || $ttl > 2**31-1) {
				return error("DNS TTL `%d' exceeds permitted limits [1, 2147483647]", $ttl);
			}
			return true;

		}

		protected function hasCnameApexRestriction(): bool
		{
			return false;
		}

		protected function getRecordId(RecordBase $r): ?string
		{

			if ($r['rr'] !== 'ANY') {
				return parent::getRecordId($r);
			}

			// populates zone cache as well
			$this->getCacheKey($r);

			// CloudFlare doesn't support ANY directly
			$chk = array_get($this->zoneCache[$r->getZone()], 'records', []);
			$key = $r['name'] === '' ? '@' : $r['name'];
			foreach ($chk as $c) {
				if (!empty($c[$key])) {
					return current($c[$key])->getMeta('id');
				}
			}

			return null;
		}


	}