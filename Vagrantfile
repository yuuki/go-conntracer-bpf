# Validate environment
['vagrant-reload', 'vagrant-vbguest'].each do |plugin|
  unless Vagrant.has_plugin?(plugin)
    raise "Vagrant plugin #{plugin} is not installed!"
  end
end

Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2010"
  config.vm.provision :shell, :privileged => false, :path => "tools/provisioning.sh"
  config.vm.synced_folder "./", "/home/vagrant/go-conntracer-bpf", mount_options: ['dmode=777','fmode=777']
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2000"
  end
end
