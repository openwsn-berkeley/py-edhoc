Installing ``edhoc``
====================

.. note::

  The commands here will install ``edhoc`` in your current Python environment.
  By default, that is your platform's user install directory.

  To keep that clean, or to use different sets or versions of libraries for different purposes,
  you may want to look into the `venv documentation`_,
  which explains both the concept of virtual environments
  and how they are used on different platforms.

  .. _`venv documentation`:  https://docs.python.org/3/library/venv


It is recommended to install the latest released version of ``edhoc``::

    $ pip3 install edhoc --upgrade

Development version
-------------------

If you want to explore ``edhoc``'s internals or consider contributing to the
project, the suggested way of operation is getting a Git checkout of the
project::

    $ git clone https://github.com/TimothyClaeys/edhoc.git
    $ cd edhoc

You can then use the project from that location, or install it with::

    $ pip3 install -e .

To build the docs locally you should navigate to the ``docs`` folder and run the the Makefile or .bat script depending on
your operating system::

    $ cd docs
    $ make html

The resulting html documentation will be build in the folder ``_build``. You can then view the documentation by opening
``index.html`` with your browser.