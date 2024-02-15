mkfifo /tmp/pipe
ubertooth-btle -f -c /tmp/pipe > /home/kali/Documents/Shared/capture.txt`

Discovery: start wireshark pipe prior to running ubertooth command to avoid error 7

airpods - nick longo airpods
galaxyBuds - galaxy buds 2 pro 2023ish
laptop - windows 11, acer nitro 5
bose - old bose quietcomfortII
phone - samsung galaxy s21 5G

airpods1  burst of case open
airpods2 - burst of case open
airpods3 - long capture of case open
airpods4 - long capture of case closed
galaxyBuds1 - medium capture of case open
galaxyBuds1 - long capture of case open
galaxyBuds3 - long capture of case closed - note, this was MUCH less frequent than the airpods1
bose1 - medium capture of searching for device
bose2 - long capture of searching for device
bose3 - do not transmit when power is off
laptop1 - short burst with bluetooth on
laptop2 - longer burst with bluetooth on
phone1 - long capture with blueooth OFF
phone2 - long capture with bluetooth ON - i noticed packets would halt when i exited the bluetooth menu (it was searching for devices)
connectionBose - capture with bose headphones connected to phone playing music
connectionBuds - capture with galaxyBuds connected to phone playing music
difference1 - galaxyBuds and airpods cases open
difference2 - galaxybuds and airpods cases closed

randomization1 - hope to see the mac change on the airpods, don't beleive I will be able to capture it though


p.s. its 16 degrees and i can't type
