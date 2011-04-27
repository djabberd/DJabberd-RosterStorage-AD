package DJabberd::RosterStorage::AD;
use strict;
use Net::LDAP;
use utf8;
use Encode;

our $VERSION = '0.01';
use base 'DJabberd::RosterStorage::SQLite';

sub _get_values {

	my $str = Encode::decode_utf8(shift);
	my @m = ();
	my $r;

	$str =~ s/^\s*(.+)\s*$/$1/;
	while($str) {
	        if ($str =~/^(["|'])/ ) {
	                $r   = $1;
	                $str =~ s/^$r([^{$r}]*)$r//;
	                push @m,$1;
	        } else {
	                $str =~ s/^([^\s]+)//;
	                push @m,$1;
	        }
	        $str =~ s/^\s+//;
	}
	return @m;

}

sub set_config_ldapserver {
        my ($self, $val) = @_;
	my ($server,@ip) = _get_values($val);
	$self->{ldapserver}{$server} = [@ip];
}

sub set_config_ldapuser {
        my ($self, $val) = @_;
	my ($server,$user) = _get_values($val);
	$self->{ldapuser}{$server} = $user;
}

sub set_config_ldappassword {
        my ($self, $val) = @_;
	my ($server,$pass) = _get_values($val);
	$self->{ldappassword}{$server} = $pass;
}

sub set_config_ldapbase {
        my ($self, $val) = @_;
	my ($server,$base) = _get_values($val);
	$self->{ldapbase}{$server} = $base;
}

sub set_config_ldapfilter {
        my ($self, $val) = @_;
	my ($server,$filter) = _get_values($val);
	$self->{ldapfilter}{$server} = $filter;
}

sub set_config_rostergroup {
        my ($self, $val) = @_;
	my ($name,$server,@groups) = _get_values($val);
	my (@dn_groups);
	unless (@groups) {
		$self->{rostergroup}{$name}{$server} = [];
		return;
	}

	my $ldap = Net::LDAP->new($self->{ldapserver}{$server});
	my $result = $ldap->bind($self->{ldapuser}{$server}, password=>$self->{ldappassword}{$server});
        $result->code && croak $result->error;
	foreach my $group (@groups) {
	        print "(&(objectClass=group)(sAMAccountName=$group))\n",
	        $result = $ldap->search(
	                base => $self->{ldapbase}{$server},
	                filter => "(&(objectClass=group)(sAMAccountName=$group))",
	                attrs => ['dn']
	        );
		foreach my $entry ($result->entries) {
			push @dn_groups, Encode::decode_utf8($entry->dn());
		}
	}
	$ldap->unbind();

	$self->{rostergroup}{$name}{$server} = [@dn_groups];
}

sub get_roster {
	my ($self, $cb, $jid) = @_;

	my $myself = lc $jid->node;
	warn "AD loading roster for $myself ...\n";

	my $on_load_roster = sub {
		my (undef, $roster) = @_;

		my $pre_ct = $roster->items;
		warn "  $pre_ct roster items prior to population...\n";

		# see which employees already in roster
		my %has;
		foreach my $it ($roster->items) {
			my $jid = $it->jid;
			$jid->as_bare_string =~ /^(\w+)\@/;
			$has{lc $1} = $it;
		}

		# add missing employees to the roster
		my $emps = _employees($self);
#		my $i = 0;
		foreach my $uid (sort keys %$emps) {
			$uid = lc $uid;
#			last if ($i++ == 110);
			next if ($uid eq $myself);
			my $dn  = $emps->{$uid}{dn};
			my $grp = $emps->{$uid}{group};
			my $ri = $has{$uid} || DJabberd::RosterItem->new(
				jid  => "$uid\@" . $jid->domain,
				name => "$dn",
				groups => ["$grp"]
			);
			$ri->subscription->set_from;
			$ri->subscription->set_to;
			$roster->add($ri);
		}
		my $post_ct = $roster->items;
		warn "  $post_ct roster items post population...\n";

		$cb->set_roster($roster);
	};

	my $cb2 = DJabberd::Callback->new({
		set_roster => $on_load_roster,
		decline    => sub { $cb->decline }
	});
	$self->SUPER::get_roster($cb2, $jid);
}

my $last_emp;
my $last_emp_time = 0;  # unixtime of last ldap suck (ldap server is slow sometimes, so don't always poll)
sub _employees {

	my ($ldap,$server,$groups,$filter,$result,$uid,$dn,%info);

	my $self = shift;

	my $now = time();
	# don't get new employees more often than once an hour.... :-)
	if ($last_emp && ($last_emp_time > $now - 3600)) {
		return $last_emp;
	}

	foreach my $group (keys %{$self->{rostergroup}}) {
		print "GROUP: $group\n";
		$server = (keys %{$self->{rostergroup}{$group}})[0];
		$groups = $self->{rostergroup}{$group}{$server};
		if (@{$groups}) {
			unless ($self->{ldapfilter}{$server} =~ /^\(/) {
				$self->{ldapfilter}{$server} = "(". $self->{ldapfilter}{$server} .")";
			}
			$filter = "(&" . $self->{ldapfilter}{$server} . "(|(" .
				join(")(", map { "memberOf=$_"} @{$groups}) . ")))",
			print "$filter\n"
		} else {
			$filter = $self->{ldapfilter}{$server};
		}

		foreach my $host (@{$self->{ldapserver}{$server}}) {
			$ldap = Net::LDAP->new($host);
			if ($ldap) {
				$result = $ldap->bind($self->{ldapuser}{$server}, password=>$self->{ldappassword}{$server});
				last unless ($result->code);
			}
			warn "bind to ldap at $host failed\n";
		}
		unless ($ldap || $result->code) {
			warn $result->error;
			warn "skip group $group. No working ldap servers found\n";
			next;
		}

		$result = $ldap->search(
			base => $self->{ldapbase}{$server},
			filter => $filter,
			attrs => ['cn','sAMAccountName']
		);

		$result->code && die $result->error;	
		foreach my $entry ($result->entries) {
			$uid = $entry->get_value('sAMAccountName');
			next if ($uid =~ /^a\-/ || $uid eq "" || $uid =~ /[^(\w|\-)]/);
			$dn = Encode::decode_utf8($entry->get_value('cn'));
			$uid = lc $server . "\\" . $uid;
			$info{$uid}{dn} = $dn;
			$info{$uid}{group} = $group;
		}
		$result = $ldap->unbind;
	}
	$last_emp_time = $now;
	return $last_emp = \%info;
}

sub finalize {
	my $self = shift;
	# Initial roster
	_employees($self);
	$self->SUPER::finalize(@_);
}

sub load_roster_item {
	my ($self, $jid, $contact_jid, $cb) = @_;

	my $both = DJabberd::Subscription->new;
	$both->set_from;
	$both->set_to;
	my $rit = DJabberd::RosterItem->new(
		jid  => $contact_jid,
		subscription => $both
	);
	$cb->set($rit);
	return;


	$self->SUPER::load_roster_item($jid, $contact_jid, $cb);
}

1;
