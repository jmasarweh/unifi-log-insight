"""Tests for enrichment.py — IP validation, TTLCache, GeoIP, AbuseIPDB."""

import time as _time
from unittest.mock import MagicMock, patch

import pytest

from enrichment import (
    AbuseIPDBEnricher,
    GeoIPEnricher,
    TTLCache,
    is_public_ip,
)


# ── is_public_ip ─────────────────────────────────────────────────────────────

class TestIsPublicIp:
    def test_public_v4(self):
        assert is_public_ip('8.8.8.8') is True

    def test_private_10(self):
        assert is_public_ip('10.0.0.1') is False

    def test_private_172(self):
        assert is_public_ip('172.16.0.1') is False

    def test_private_192(self):
        assert is_public_ip('192.168.1.1') is False

    def test_loopback(self):
        assert is_public_ip('127.0.0.1') is False

    def test_ipv6_loopback(self):
        assert is_public_ip('::1') is False

    def test_ipv6_ula(self):
        assert is_public_ip('fc00::1') is False

    def test_multicast(self):
        assert is_public_ip('224.0.0.1') is False

    def test_empty(self):
        assert is_public_ip('') is False

    def test_none(self):
        assert is_public_ip(None) is False

    def test_invalid(self):
        assert is_public_ip('not-an-ip') is False

    def test_public_ipv6(self):
        assert is_public_ip('2001:4860:4860::8888') is True


# ── TTLCache ─────────────────────────────────────────────────────────────────

class TestTTLCache:
    def test_set_and_get(self):
        cache = TTLCache(ttl_seconds=60)
        cache.set('key1', {'value': 42})
        assert cache.get('key1') == {'value': 42}

    def test_get_expired(self, monkeypatch):
        cache = TTLCache(ttl_seconds=10)
        # Set an entry at time 1000
        real_time = [1000.0]
        monkeypatch.setattr(_time, 'time', lambda: real_time[0])
        cache.set('key1', {'value': 1})
        # Advance past TTL
        real_time[0] = 1011.0
        assert cache.get('key1') is None

    def test_get_within_ttl(self, monkeypatch):
        cache = TTLCache(ttl_seconds=10)
        real_time = [1000.0]
        monkeypatch.setattr(_time, 'time', lambda: real_time[0])
        cache.set('key1', {'value': 1})
        real_time[0] = 1005.0
        assert cache.get('key1') == {'value': 1}

    def test_delete(self):
        cache = TTLCache()
        cache.set('key1', {'value': 1})
        cache.delete('key1')
        assert cache.get('key1') is None

    def test_delete_nonexistent(self):
        cache = TTLCache()
        cache.delete('missing')  # Should not raise

    def test_size(self):
        cache = TTLCache()
        assert cache.size() == 0
        cache.set('a', {})
        cache.set('b', {})
        assert cache.size() == 2

    def test_get_miss(self):
        cache = TTLCache()
        assert cache.get('nonexistent') is None

    def test_set_existing_key_replaces_value_without_growing(self):
        cache = TTLCache(ttl_seconds=60, max_entries=3)

        cache.set('a', {'value': 1})
        cache.set('a', {'value': 2})

        assert cache.size() == 1
        assert cache.get('a') == {'value': 2}

    @pytest.mark.parametrize(
        ('kwargs', 'message'),
        [
            ({'max_entries': 0}, 'positive'),
            ({'max_entries': -1}, 'positive'),
            ({'max_entries': 1, 'prune_trigger_ratio': 0.99}, '>= 1.0'),
            ({'max_entries': 1, 'prune_target_ratio': 0}, 'within'),
            ({'max_entries': 1, 'prune_target_ratio': 1.01}, 'within'),
        ],
    )
    def test_constructor_validation(self, kwargs, message):
        with pytest.raises(ValueError, match=message):
            TTLCache(**kwargs)

    def test_set_prunes_expired_entries_at_watermark(self, monkeypatch):
        cache = TTLCache(ttl_seconds=10, max_entries=3)
        real_time = [1000.0]
        monkeypatch.setattr(_time, 'time', lambda: real_time[0])

        cache.set('a', {'value': 'a'})
        cache.set('b', {'value': 'b'})
        cache.set('c', {'value': 'c'})

        real_time[0] = 1011.0
        cache.set('d', {'value': 'd'})

        assert cache.size() == 1
        assert cache.get('a') is None
        assert cache.get('b') is None
        assert cache.get('c') is None
        assert cache.get('d') == {'value': 'd'}

    def test_set_evicts_lru_down_to_watermark_target(self):
        cache = TTLCache(ttl_seconds=60, max_entries=3)

        cache.set('a', {'value': 'a'})
        cache.set('b', {'value': 'b'})
        cache.set('c', {'value': 'c'})
        assert cache.get('a') == {'value': 'a'}  # refresh recency
        cache.set('d', {'value': 'd'})

        assert cache.size() == 2
        assert cache.get('a') == {'value': 'a'}
        assert cache.get('d') == {'value': 'd'}
        assert cache.get('b') is None
        assert cache.get('c') is None

    def test_set_prunes_expired_then_evicts_lru_when_still_over_cap(self, monkeypatch):
        cache = TTLCache(
            ttl_seconds=10,
            max_entries=5,
            prune_trigger_ratio=2.0,
            prune_target_ratio=0.8,
        )
        real_time = [1000.0]
        monkeypatch.setattr(_time, 'time', lambda: real_time[0])

        for key in ('a', 'b', 'c'):
            cache.set(key, {'value': key})

        real_time[0] = 1005.0
        for key in ('d', 'e', 'f', 'g', 'h', 'i'):
            cache.set(key, {'value': key})

        real_time[0] = 1011.0
        cache.set('j', {'value': 'j'})

        assert cache.size() == 4
        for key in ('a', 'b', 'c', 'd', 'e', 'f'):
            assert cache.get(key) is None
        for key in ('g', 'h', 'i', 'j'):
            assert cache.get(key) == {'value': key}


# ── GeoIPEnricher ────────────────────────────────────────────────────────────

class TestGeoIPEnricher:
    def test_no_reader_returns_empty(self, tmp_path):
        enricher = GeoIPEnricher(db_dir=str(tmp_path))
        assert enricher.city_reader is None
        assert enricher.asn_reader is None
        result = enricher.lookup('8.8.8.8')
        assert result == {}

    def test_lookup_with_mocked_readers(self):
        enricher = GeoIPEnricher(db_dir='/nonexistent')

        # Mock city reader
        city_resp = MagicMock()
        city_resp.country.iso_code = 'US'
        city_resp.city.name = 'Mountain View'
        city_resp.location.latitude = 37.386
        city_resp.location.longitude = -122.084
        enricher.city_reader = MagicMock()
        enricher.city_reader.city.return_value = city_resp

        # Mock ASN reader
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 15169
        asn_resp.autonomous_system_organization = 'Google LLC'
        enricher.asn_reader = MagicMock()
        enricher.asn_reader.asn.return_value = asn_resp

        result = enricher.lookup('8.8.8.8')
        assert result['geo_country'] == 'US'
        assert result['geo_city'] == 'Mountain View'
        assert result['asn_number'] == 15169
        assert result['asn_name'] == 'Google LLC'

    def test_lookup_exception_handled(self):
        enricher = GeoIPEnricher(db_dir='/nonexistent')
        enricher.city_reader = MagicMock()
        enricher.city_reader.city.side_effect = Exception('db error')
        # Should not raise, just return empty
        result = enricher.lookup('8.8.8.8')
        assert 'geo_country' not in result


# ── AbuseIPDBEnricher ────────────────────────────────────────────────────────

class TestAbuseIPDBEnricher:
    def test_disabled_returns_empty(self):
        enricher = AbuseIPDBEnricher(api_key='')
        assert enricher.lookup('1.2.3.4') == {}

    def test_excluded_ip_returns_empty(self):
        enricher = AbuseIPDBEnricher(api_key='test-key')
        enricher.exclude_ip('1.2.3.4')
        assert enricher.lookup('1.2.3.4') == {}

    def test_cached_result_no_api_call(self):
        enricher = AbuseIPDBEnricher(api_key='test-key')
        enricher.cache.set('1.2.3.4', {'threat_score': 75})
        result = enricher.lookup('1.2.3.4')
        assert result == {'threat_score': 75}

    @patch('enrichment.requests.get')
    def test_api_call_on_cache_miss(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'data': {
                'abuseConfidenceScore': 90,
                'reports': [{'categories': [14, 18]}],
            }
        }
        mock_resp.headers = {
            'X-RateLimit-Limit': '1000',
            'X-RateLimit-Remaining': '999',
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        enricher = AbuseIPDBEnricher(api_key='test-key')
        result = enricher.lookup('1.2.3.4')
        assert result['threat_score'] == 90
        assert '14' in result['threat_categories']
        assert '18' in result['threat_categories']
        mock_get.assert_called_once()

    @patch('enrichment.requests.get')
    def test_429_returns_empty(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.headers = {'Retry-After': '3600'}
        mock_get.return_value = mock_resp

        enricher = AbuseIPDBEnricher(api_key='test-key')
        result = enricher.lookup('1.2.3.4')
        assert result == {}
        assert enricher._paused_until > _time.time()
