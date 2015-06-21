class Utilities
{
    public:

        static void showHex (unsigned char* data, int Size)
        {
            unsigned char a , line[17] , c;
            int j;

            //loop over each character and print
            for(int i=0 ; i < Size ; i++)
            {
                c = data[i];

                //Print the hex value for every character , with a space
                printf(" %.2x", (unsigned int) c);

                //Add the character to data line
                a = ( c >=32 && c <=128) ? (unsigned char) c : '.';

                line[i%16] = a;

                //if last character of a line , then print the line - 16 characters in 1 line
                if( (i!=0 && (i+1)%16==0) || i == Size - 1)
                {
                    line[i%16 + 1] = '\0';

                    //print a big gap of 10 characters between hex and characters
                    printf("          ");

                    //Print additional spaces for last lines which might be less than 16 characters in length
                    for( j = strlen((const char *)line) ; j < 16; j++)
                    {
                        printf("   ");
                    }

                    printf("%s \n" , line);
                }
            }
        }


        static bool isOdd(int number)
        {
            return (number & 1);
        }


        static uint16_t caculateChecksum(void *buffer, uint16_t length, uint32_t initialValue)
        {
              /* Compute Internet Checksum for "length" bytes
                *         beginning at location "addr".
                */

            uint16_t *addr = (uint16_t *)buffer;
            register uint32_t sum = initialValue;


            while (length > 1)
            {
                /*  This is the inner loop */
                sum += ntohs(* addr++);
                length -= 2;
            }
               /*  Add left-over byte, if any */
            if (length > 0)
                sum += ntohs(* (uint8_t *) addr);

               /*  Fold 32-bit sum to 16 bits */
            while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

            return ntohs(~sum);
        }
};
