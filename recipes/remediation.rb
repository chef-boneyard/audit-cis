directory '/tmp' do
  recursive true
end

directory '/var' do
  recursive true
end

mount '/tmp' do
  device '/dev/sdb1'
  fstype 'xfs'
  options ['nodev', 'nosuid', 'noexec']
  action [:enable, :mount]
end

mount '/var' do
  device '/dev/sdb2'
  fstype 'xfs'
  action [:enable, :mount]
end

directory '/var/tmp' do
  recursive true
end

mount '/var/tmp' do
  device '/tmp'
  options 'bind'
  action [:enable, :mount]
end

directory '/var/log' do
  recursive true
end

mount '/var/log' do
  device '/dev/sdb5'
  fstype 'xfs'
  action [:enable, :mount]
end

directory '/var/log/audit' do
  recursive true
end

mount '/var/log/audit' do
  device '/dev/sdb6'
  fstype 'xfs'
  action [:enable, :mount]
end

mount '/home' do
  device '/dev/sdb3'
  fstype 'xfs'
  options 'nodev'
  action [:enable, :mount]
end
