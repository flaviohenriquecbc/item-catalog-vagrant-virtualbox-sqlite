# Item Catalog

Item catalog project for Udacity Full Stack Nanodegree

### Requirements

* VirtualBox installation (https://www.virtualbox.org/wiki/Downloads)
* Vagrant installation (https://www.vagrantup.com/downloads)
* Clone of Vagrant VM for ud197 (git clone http://github.com/udacity/fullstack-nanodegree-vm fullstack)
* To run the test suite (exercising all of the Python functions for the tournament database):
* Python
* SQLite databse
* Google Developer Credentials to use Google Authentication
* Facebook Developer Credentials to use Facebook Authentication

From a GitHub shell:

```
$ cd fullstack/vagrant
$ vagrant up (you can turn off the VM with 'vagrant halt')
$ vagrant ssh (from here you can type 'exit' to log out)
```

### Running the project
1. Clone the project
2. To initialize the SQLite database:
```python
    $ python database_setup.py
```

3. Run the following unit tests code:

```python
    $ python project.py
```

Tadaa! You have the item catalog working
