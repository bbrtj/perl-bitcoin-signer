package Signer::Util;

use v5.38;
use Try::Tiny;
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Constants;
use Bitcoin::Crypto::Bech32 qw(decode_segwit get_hrp);
use Bitcoin::Crypto::Base58 qw(decode_base58check);

sub get_address_type ($address, $network = Bitcoin::Crypto::Network->get)
{
	state $checks = {
		P2TR => sub ($network, $address) {
			my $data = decode_segwit($address);
			my $version = unpack 'C', substr $data, 0, 1, '';
			return $network->segwit_hrp eq get_hrp($address)
				&& $version == Bitcoin::Crypto::Constants::taproot_witness_version
				;
		},
		P2WSH => sub ($network, $address) {
			my $data = decode_segwit($address);
			my $version = unpack 'C', substr $data, 0, 1, '';
			return $network->segwit_hrp eq get_hrp($address)
				&& $version == Bitcoin::Crypto::Constants::segwit_witness_version
				&& length $data == 32
				;
		},
		P2WPKH => sub ($network, $address) {
			my $data = decode_segwit($address);
			my $version = unpack 'C', substr $data, 0, 1, '';
			return $network->segwit_hrp eq get_hrp($address)
				&& $version == Bitcoin::Crypto::Constants::segwit_witness_version
				&& length $data == 20
				;
		},
		P2SH => sub ($network, $address) {
			return $network->p2sh_byte eq substr decode_base58check($address), 0, 1;
		},
		P2PKH => sub ($network, $address) {
			return $network->p2pkh_byte eq substr decode_base58check($address), 0, 1;
		},
	};

	my $type;
	foreach my $result (keys $checks->%*) {
		my $check = $checks->{$result};

		try {
			$type = $result if $check->($network, $address);
		};
	}

	die "unknown address type $address" unless defined $type;
	return $type;
}

