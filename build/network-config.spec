Name:		bms-network-config
Version:	1.0
Release:	7.%_distros
Summary:	bms-network-config

Group:		Development/Tools
License:	GPL
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	python
BuildRequires:	dos2unix
Requires:	python
Requires:	cloud-init
BuildRoot:	%{_tmppath}/%{name}-%{version}-build


%define _unpackaged_files_terminate_build 0


%description
This is a tool to config network

%prep
cd %{_sourcedir} 
tar xzvf %{name}-%{version}.tar.gz
cp %{name}-%{version}/network_config.py.%_distros  %{name}-%{version}/bms-network_config.py
if [ "%{?_distros}" == "suse11" ]; then
   cp %{name}-%{version}/bms-network-config-suse114  %{name}-%{version}/bms-network-config
else
   cp %{name}-%{version}/bms-network-config-rhel6x  %{name}-%{version}/bms-network-config
fi
tar czvf %{name}-%{version}.tar.gz  %{name}-%{version}
%setup -c

%install
cd %{name}-%{version}
dos2unix bms-network_config.py
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/opt/huawei/network_config
%if "0%{?_distros}"   
%if "%{?_distros}" != "centosRedhat6" && "%{?_distros}" != "suse11" 
	mkdir -p $RPM_BUILD_ROOT/%{_unitdir}
	cp -p bms-network-config.service $RPM_BUILD_ROOT/%{_unitdir}
	if [ -f $RPM_BUILD_ROOT/%{_initddir}/bms-network-config ] ; then
		rm $RPM_BUILD_ROOT/%{_initddir}/bms-network-config
	fi

	if [ -f ${RPM_BUILD_ROOT}/%{_sbindir}/rcnetwork-config ] ; then
		rm  ${RPM_BUILD_ROOT}/%{_sbindir}/rcnetwork-config
	fi
%else 
	mkdir -p ${RPM_BUILD_ROOT}/%{_initddir}
	mkdir -p ${RPM_BUILD_ROOT}/%{_sbindir}
	if [ -f $RPM_BUILD_ROOT/%{_unitdir} ] ; then
		rm $RPM_BUILD_ROOT/%{_unitdir}/bms-network-config.service
	fi
	cp -p bms-network-config $RPM_BUILD_ROOT/%{_initddir}
	ln -sf "%{_initddir}/bms-network-config" "${RPM_BUILD_ROOT}/%{_sbindir}/rcnetwork-config"
%endif
%endif

install -m 0500 bms-network_config.py $RPM_BUILD_ROOT/opt/huawei/network_config/bms-network_config.py
install -m 0500 bms-network-config.conf $RPM_BUILD_ROOT/opt/huawei/network_config/bms-network-config.conf
ln -sf /opt/huawei/network_config/bms-network_config.py $RPM_BUILD_ROOT/usr/bin/bms-network_config
%clean
rm -rf $RPM_BUILD_ROOT

%pre

%post
if [ $1 -eq 1 ] ; then
%if "%{?_distros}" != "centosRedhat6"   && "%{?_distros}" != "suse11" 
	/bin/systemctl enable bms-network-config.service >/dev/null 2>&1 || :
%else 
	/sbin/chkconfig --add bms-network-config
	/sbin/chkconfig --level 5 bms-network-config on
%endif
fi

%preun
if [ $1 -eq 0 ] ; then
%if "%{?_distros}" != "centosRedhat6"  && "%{?_distros}" != "suse11" 
	/bin/systemctl --no-reload disable bms-network-config.service >/dev/null 2>&1 || :
%else
    /sbin/service bms-network-config stop >/dev/null 2>&1 || :
    /sbin/chkconfig --del bms-network-config || :	
%endif
fi

%postun
%if "%{?_distros}" != "centosRedhat6"  && "%{?_distros}" != "suse11"
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%endif

%files
%defattr(-,root,root)
/opt/huawei/network_config/*
/usr/bin/bms-network_config

%if "%{?_distros}" == "centosRedhat6" || "%{?_distros}" == "suse11"
	%{_sbindir}/rcnetwork-config
	%attr(0755, root, root) %{_initddir}/bms-network-config
%else
	%{_unitdir}/bms-network-config.service
%endif

#%exclude /opt/huawei/network_config/*.pyc
#%exclude /opt/huawei/network_config/*.pyo

%changelog
* Mon May 22 2017 huawei
- Init
