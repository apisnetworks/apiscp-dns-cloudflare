<?php declare(strict_types=1);
	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * Unauthorized copying of this file, via any medium, is
	 * strictly prohibited without consent. Any dissemination of
	 * material herein is prohibited.
	 *
	 * For licensing inquiries email <licensing@apisnetworks.com>
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, March 2019
	 */

	namespace Opcenter\Dns\Providers\Cloudflare;

	class Record extends \Opcenter\Dns\Record
	{
		/**
		 * Remove bunched components from parameter before add
		 *
		 * @param Record $r
		 * @return array
		 */
		public function spreadParameters(): array
		{
			if ($this->matches('rr', 'MX')) {
				$this['parameter'] = $this->getMeta('data');
				return [
					'priority' => (int)$this->getMeta('priority'),
				];
			}
			if ($this->matches('rr', 'SRV')) {
				$this['parameter'] = substr($this['parameter'], strrpos($this['parameter'], ' ')+1);
				return [
					'data' => [
						'service'  => $this->getMeta('service'),
						'proto'    => $this->getMeta('protocol'),
						'priority' => (int)$this->getMeta('priority'),
						'weight'   => (int)$this->getMeta('weight'),
						'port'     => (int)$this->getMeta('port'),
						'target'   => $this['parameter'],
					]
				];
			}
			if ($this->matches('rr', 'CAA')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'flags' => (int)$this->getMeta('flags'),
						'tag'   => $this->getMeta('tag'),
						'value' => $this->getMeta('data')
					]
				];
			}
			if ($this->matches('rr', 'CERT')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'certificate' => $this->getMeta('data'),
						'type'      => (int)$this->getMeta('type'),
						'key_tag'   => (int)$this->getMeta('key_tag'),
						'algorithm' => (int)$this->getMeta('algorithm')
					]
				];
			}

			if ($this->matches('rr', 'DNSKEY')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'flags'      => (int)$this->getMeta('flags'),
						'protocol'   => (int)$this->getMeta('protocol'),
						'algorithm'  => (int)$this->getMeta('algorithm'),
						'public_key' => (string)$this->getMeta('data')
					]
				];
			}

			if ($this->matches('rr', 'DS')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'key_tag'     => (int)$this->getMeta('key_tag'),
						'algorithm'   => (int)$this->getMeta('algorithm'),
						'digest_type' => (int)$this->getMeta('digest_type'),
						'digest'      => (string)$this->getMeta('data')
					]
				];
			}

			if ($this->matches('rr', 'LOC')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'lat_degrees'    => (int)$this->getMeta('lat_degrees'),
						'lat_minutes'    => (int)$this->getMeta('lat_minutes'),
						'lat_seconds'    => (int)$this->getMeta('lat_seconds'),
						'lat_direction'  => $this->getMeta('lat_direction'),
						'long_degrees'   => (int)$this->getMeta('long_degrees'),
						'long_minutes'   => (int)$this->getMeta('long_minutes'),
						'long_seconds'   => (int)$this->getMeta('long_seconds'),
						'long_direction' => $this->getMeta('long_direction'),
						'altitude'       => (float)$this->getMeta('altitude'),
						'size'           => (int)$this->getMeta('size'),
						'precision_horz' => (float)$this->getMeta('precision_horz'),
						'precision_vert' => (float)$this->getMeta('precision_vert'),
					]
				];
			}

			if ($this->matches('rr', 'NAPTR')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'order'       => (int)$this->getMeta('order'),
						'preference'  => (int)$this->getMeta('preference'),
						'flags'       => $this->trim((string)$this->getMeta('flags')),
						'service'     => $this->trim((string)$this->getMeta('service')),
						'regex'       => $this->trim((string)$this->getMeta('regex')),
						'replacement' => $this->trim((string)$this->getMeta('data'))
					]
				];
			}

			if ($this->matches('rr', 'SMIMEA')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'usage'         => (int)$this->getMeta('order'),
						'selector'      => (int)$this->getMeta('preference'),
						'matching_type' => (int)$this->getMeta('flags'),
						'certificate'   => (string)$this->getMeta('data'),
					]
				];
			}

			if ($this->matches('rr', 'SSHFP')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'algorithm'   => (int)$this->getMeta('algorithm'),
						'type'        => (int)$this->getMeta('type'),
						'fingerprint' => (string)$this->getMeta('data')
					]
				];
			}

			if ($this->matches('rr', 'TLSA')) {
				$this['parameter'] = '';

				return [
					'data' => [
						'usage'         => (int)$this->getMeta('usage'),
						'selector'      => (int)$this->getMeta('selector'),
						'matching_type' => (int)$this->getMeta('matching_type'),
						'certificate'   => (string)$this->getMeta('data'),
					]
				];
			}

			if ($this->matches('rr', 'URI')) {
				$this['parameter'] = '';
				return [
					'data' => [
						'priority'       => (int)$this->getMeta('priority'),
						'weight'         => (int)$this->getMeta('weight'),
						'content'        => $this->trim((string)$this->getMeta('data')),
					]
				];
			}
			return [];
		}

		public function is(\Opcenter\Dns\Record $r)
		{
			if (parent::is($r)) {
				return true;
			}
			if ($r['rr'] !== 'TXT') {
				return false;
			}

			// apply second loop
			$r['parameter'] = $this->trim($r['parameter']);

			return parent::is($r);
		}
	}