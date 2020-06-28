#!/usr/bin/perl

sub make_visible {
    my ($tree) = @_;
    my @files = (`cd hot/build/${tree}/new; find -type f -print0`);
    for my $file (@files) {
	chomp $file;
	my $path = $file;
	$path =~ s/^\.\///;
	$path =~ s/\//\/versions\/hot\/content\//g;
	warn "new file $file";
	symlink($tree, "cold/versions/hot/content/${path}/versions/hot");
    }
}

sub cancel_build {
    my ($tree) = @_;
    my @files = (`cd hot/build/${tree}/new; find -type f -print0`);
    for my $file (@files) {
	chomp $file;
	my $path = $file;
	$path =~ s/^\.\///;
	$path =~ s/\//\/content\//g;
	warn "deleting file $file";
	system("rm -rf cold/content/${path}")
    }
}

$/ = "\0";
while (<>) {
    chomp;
    warn $_;
    if (/^start (\d+) (.*)$/) {
	my $tree = ${1};
	my $file = ${2};
	system("mkdir hot/build/${tree}");
	my $pid = fork();
	if ($pid == 0) {
	    chdir("hot/build/${tree}/work");
	    system("make ${file} > /dev/stderr");
	    exit 0;
	}
	waitpid($pid, 0);
	if ($? == 0) {
	    make_visible($tree);
	}
	$| = 1;
	print "${tree}\0";
    } elsif (/^cancel (\d+)/) {
	cancel_build $1;
    }
}
