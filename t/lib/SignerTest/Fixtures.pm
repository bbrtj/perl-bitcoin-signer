package SignerTest::Fixtures;

use v5.40;
use Exporter qw(import);

our @EXPORT_OK = qw(test_mnemonics);

use Bitcoin::Crypto qw(btc_extprv);
use Bitcoin::Crypto::Constants qw(:bip44);

sub test_mnemonics ($case_index, @accounts)
{
	state @cases = (
		{
			mnemonic =>
				'equal runway into girl sell clown marriage museum hurdle trim what service swift pulse adjust hover achieve burst bread fog maze cream because phone',
			mnemonic_password => 'test',
		}
	);

	my $case = $cases[$case_index] // "no such test case $case_index";
	$case->{master_key} //= btc_extprv->from_mnemonic($case->{mnemonic}, $case->{mnemonic_password}, 'en');

	foreach my $account (@accounts) {
		next if defined $case->{account_keys}{$account};

		foreach my $purpose (
			BIP44_PURPOSE,
			BIP44_COMPAT_PURPOSE,
			BIP44_SEGWIT_PURPOSE,
			BIP44_TAPROOT_PURPOSE,
			)
		{
			$case->{account_keys}{$account}{$purpose} = $case->{master_key}->derive_key_bip44(
				purpose => $purpose,
				account => $account,
				get_account => true
			);
		}
	}

	return $case;
}

