package Signer::Transaction;

use v5.38;
use Moo;
use Mooish::AttributeBuilder;
use Types::Common qw(InstanceOf HashRef);
use Try::Tiny;
use Bitcoin::Crypto qw(btc_transaction);
use Bitcoin::Crypto::Network;
use Bitcoin::Crypto::Bech32 qw(get_hrp);
use Bitcoin::Crypto::Base58 qw(decode_base58check);

use Signer::Input::Transaction;

has param 'parent' => (
	isa => InstanceOf ['Signer'],
	handles => {
		config => 'signer_config',
	},
);

has param 'input' => (
	coerce => (InstanceOf ['Signer::Input::Transaction'])
		->plus_coercions(HashRef, q{ Signer::Input::Transaction->new($_) }),
);

with qw(Signer::Role::HasMasterKey);

sub get_excess_sats ($self, $tx, $fee_rate)
{
	my $size = $tx->virtual_size;
	my $current_fee_rate = $tx->fee_rate;
	my $excess_sats = $size * ($current_fee_rate - $fee_rate);

	return $excess_sats;
}

sub get_change_key ($self)
{
	my $change = $self->input->change;
	die 'no change address specified'
		unless defined $change;

	# dies if not found
	$self->find_key($change, change => 1);
	return $change;
}

sub find_key ($self, $address, %opts)
{
	my %checks = (
		84 => sub ($network, $address) {
			return $network->segwit_hrp eq get_hrp($address);
		},
		49 => sub ($network, $address) {
			return $network->p2sh_byte eq unpack 'C', decode_base58check $address;
		},
		44 => sub ($network, $address) {
			return $network->p2pkh_byte eq unpack 'C', decode_base58check $address;
		},
	);

	my $network = Bitcoin::Crypto::Network->get_default;
	my $purpose;
	foreach my $result (keys %checks) {
		my $check = $checks{$result};

		try {
			$purpose = $result if $check->($network, $address);
		};
	}

	die "unknown address type $address" unless defined $purpose;

	my $input = $self->input;
	my @config = (
		($opts{change} ? () : {
			change => 0,
			from => $input->address_search_from,
			to => $input->address_search_to,
		}),
		{
			change => 1,
			from => $input->change_search_from,
			to => $input->change_search_to,
		},
	);

	my $acc_key = $self->master_key($purpose);
	for my $conf (@config) {
		foreach my $ind ($conf->{from} .. $conf->{to}) {
			my $key = $acc_key->derive_key_bip44(
				get_from_account => 1,
				change => $conf->{change},
				index => $ind,
			);

			return $key
				if $key->get_public_key->get_address eq $address;
		}
	}

	die "address $address not found in this master key";
}

sub get_tx ($self)
{
	my $input = $self->input;

	my $tx = btc_transaction->new;
	my @keys;
	my sub sign {
		foreach my $key_ind (keys @keys) {
			my $key = $keys[$key_ind];
			$key->sign_transaction($tx, signing_index => $key_ind);
		}
	}

	foreach my $utxo ($input->inputs->@*) {
		# find input with master_key (either change or normal)
		# need info on last used address
		push @keys, $self->find_key($utxo->output->locking_script->get_address);

		$tx->add_input(utxo => $utxo);
	}

	foreach my $output ($input->outputs->@*) {
		$tx->add_output($output);
	}

	$tx->set_rbf;

	if ($input->chane) {

		# presign to get size and adjust the fee
		sign;

		my $excess_fee = $self->get_excess_sats($tx, $input->fee_rate);

		if ($excess_fee > $tx->virtual_size) {
			# add change address, but keep in mind it will make the
			# transaction slightly bigger, so only do it if excess sats are
			# more than transaction virtual size
			my $prv = $self->get_change_key;
			$tx->add_output(
				locking_script => [P2WPKH => $prv->get_public_key->get_address],
				value => $excess_fee - 35, # approximate 35 vbytes for the output
			);
		}
		elsif ($excess_fee < 0) {
			die 'not enough value left for fee';
		}
	}

	# final signing
	sign;
	return $tx;
}

