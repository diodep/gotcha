#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

 
typedef struct linklist
{
    uint32_t data;
    int mask;
    int count;
    struct linklist *next;
}list, *plist;

 
void order_insert_list(plist *head, uint32_t number, int mask, int count)
{
    plist p_new = (plist)malloc(sizeof(list));
    plist pre = NULL;            
    p_new->data = number;        
    p_new->mask = mask;
    p_new->count = count;
    p_new->next = NULL;         

    plist temp; // = (plist)malloc(sizeof(list));
    temp = *head;   

     
    if (NULL == *head)
    {
        *head = p_new;
        return;
    }

     
    if (p_new->data < temp->data)
    {
        p_new->next = temp; 
        *head = p_new;
        return;
    }
    else
    {
        while (NULL != temp)
        {   
            if (p_new->data >= temp->data) 
            {
                if(p_new->data == temp->data)
                {
                    //printf("equal\n");
                    temp->count = temp->count > p_new->count? temp->count: p_new->count;
                    free(p_new);
                    return ;
                }
                pre = temp;     
                temp= temp->next; 
                continue;
            }
            else
            {
                p_new->next = temp; 
                pre->next = p_new;  
                break;
            }           
        }
        if (NULL == temp) 
        {
            p_new->next = NULL;
            pre->next = p_new;    
        }
    }
}

void print_ip_verbose(uint32_t ip, int mask, int count)
{
    printf("%u.%u.%u.%u/%u or %u\n", ip >> 24, (ip & 0x00ff0000) >> 16, (ip & 0x0000ff00) >> 8, ip & 0xff, mask, count);
}

void print_ip(uint32_t ip, int mask)
{
    printf("%u.%u.%u.%u/%u", ip >> 24, (ip & 0x00ff0000) >> 16, (ip & 0x0000ff00) >> 8, ip & 0xff, mask);
}

void print_list(plist head)
{
    plist elem = head; 
    int count = 0;
    printf("protocol static foreign_routes {\nipv4 { table gw_feed_in_v4; };\n");
    while (elem != NULL)
    {
        //printf("%u/%d\n", elem->data, elem->mask);
        printf("\troute ");
        print_ip(elem->data, elem->mask);
        printf(" unreachable;\n");
        elem = elem->next;
        count ++;
    }
    printf("# count = %d\n}\n", count);
}

uint8_t count_to_mask(uint32_t count)
{
    uint8_t mask = 33;
    while(count > 0)
    {
        mask --;
        count >>= 1;
    }
    return mask;
}

uint8_t check_mask(uint32_t count)
{

}

//range to CIDR
void add_split_route(plist *head, uint32_t start_ip, uint32_t count)
{
#if 0
    uint32_t rounded = (1 << (32 - count_to_mask(count)));
    uint32_t subnet = start_ip & (rounded - 1);
    uint32_t net = start_ip - subnet;
    if(rounded != count || net != start_ip) //如果数量没法被整除，则生成一堆路由
    {
        printf("Need to split route: %d %d ", rounded, count);
        print_ip_verbose(start_ip, count_to_mask(count), count);
        while(count > 0)
        {
            subnet = subnet == 0? rounded: subnet;
            printf("netmask = %x, subnet = %x, net = %x\n", rounded - 1, subnet, net);
            order_insert_list(head, start_ip, count_to_mask(subnet), subnet);
            printf("Added part route:");
            print_ip_verbose(start_ip, count_to_mask(subnet), subnet);
            start_ip += subnet;
            count -= subnet;

            rounded = (1 << (32 - count_to_mask(count)));
            subnet = start_ip & (rounded - 1);
            //printf("rounded %d\n", rounded);
            subnet = subnet == 0? rounded: subnet;
        }
        //order_insert_list(head, )
    }
    else
    { //如果能被整除，直接插入
        printf("Directly agg: ");
        print_ip_verbose(start_ip, 0, count);
        order_insert_list(head, start_ip, count_to_mask(count), count);
    }
#else
    uint32_t cidr2mask[] = 
    {
                0x00000000, 0x80000000, 0xC0000000, 
                0xE0000000, 0xF0000000, 0xF8000000, 
                0xFC000000, 0xFE000000, 0xFF000000, 
                0xFF800000, 0xFFC00000, 0xFFE00000, 
                0xFFF00000, 0xFFF80000, 0xFFFC0000, 
                0xFFFE0000, 0xFFFF0000, 0xFFFF8000, 
                0xFFFFC000, 0xFFFFE000, 0xFFFFF000, 
                0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 
                0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0, 
                0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8, 
                0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF
    };
    uint32_t endaddr = start_ip + count;
    while(endaddr > start_ip)
    {
        int onesize = 32;
        while(onesize > 0)
        {
            uint32_t mask = cidr2mask[onesize - 1];
            uint32_t net = start_ip & mask;
            if(net != start_ip)
                break;
            onesize --;
        }
        int maxsize = endaddr - start_ip;
        int logmax = 32 - count_to_mask(maxsize);

        int max_diff = 32 - logmax;
        if(onesize < max_diff)
            onesize = max_diff;

        //printf("maxsize = %d, log maxsize = %d\n", maxsize, logmax);

        //print_ip_verbose(start_ip, onesize, 1 << (32 - onesize));
        order_insert_list(head, start_ip, onesize, 1 << (32 - onesize));

        start_ip += (1 << (32 - onesize));
    }
#endif
}

void gen_agg_table(plist old_tab, plist *new_tab)
{
    plist elem = old_tab; 
    *new_tab = NULL;
    uint32_t start_ip, end_ip, mask, count, count_sum;
    while (elem != NULL)
    {
    repeat:
        start_ip = elem->data;
        count = elem->count;
        //print_ip_verbose(start_ip, count_to_mask(elem->count), count);

        elem = elem->next;
        if(elem == NULL) //添加最后一个IP
        {
            add_split_route(new_tab, start_ip, count);
        }
        count_sum = count;
        while (elem != NULL)
        {
            end_ip = elem->data;
            //print_ip_verbose(end_ip, count_to_mask(elem->count), elem->count);
            if(end_ip == count_sum + start_ip) //如果下一个IP刚好挨着
            {
                count_sum += elem->count;
            }
            else
            { //增加IP
                //print_ip_verbose(end_ip, 0, count_sum);
                add_split_route(new_tab, start_ip, count_sum);
                goto repeat;
            }
            elem = elem->next;
        }
    }
}

void gen_reverse_table(plist positive_table, plist *reverse_table)
{
    plist elem = positive_table;
    *reverse_table = NULL;
    //int start_ip = 0x01000000; //1.0.0.0
    int end_ip = 0xE0000000; //224.0.0.0
    uint32_t dst_ip;
    uint32_t dst_end_ip;
    uint32_t count;
    while (elem != NULL)
    {
    
        dst_ip = elem->data;
        count = elem->count;
        //printf("start ip ");
        //print_ip_verbose(elem->data, count_to_mask(elem->count), elem->count);

repeat:
        elem = elem->next;
        if(elem == NULL)
            break;
        //printf("end ip ");
        //print_ip_verbose(elem->data, count_to_mask(elem->count), elem->count);
        dst_end_ip = elem->data;
        if(count + dst_ip >= dst_end_ip) //如果下个IP刚好挨着
        {
            count = dst_end_ip + elem->count - dst_ip;
            //printf("count = %d\n", count);
            goto repeat; //重来
        }
        
        //printf("ip range ");
        //print_ip_verbose(dst_ip + count, 0, dst_end_ip - dst_ip - count);
        add_split_route(reverse_table, count + dst_ip, dst_end_ip - dst_ip - count);
        
        //elem = elem->next;
    }
}

void main()
{
    int number;
    plist head, new_tab, reverse_tab, agg_tab;      
    head = NULL;
    new_tab = NULL;
    char content[128];

    uint32_t start_ip, end_ip;
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t ip_count;
    int mask;
    FILE *fp = fopen("esst_service.txt", "r");
    while(!feof(fp))
    {
        fgets(content, 128, fp);
    #if 0
        sscanf(content + 1, "%d.%d.%d.%d-%d.%d.%d.%d", &a, &b, &c, &d, &e, &f, &g, &h);
        //printf("%d.%d.%d.%d-%d.%d.%d.%d\n", a, b, c, d, e, f, g, h);

        start_ip = (a & 0xff) * 16777216 + (b & 0xff) *65536 + (c & 0xff) * 256 + (d & 0xff);
        end_ip = (e & 0xff) * 16777216 + (f & 0xff) *65536 + (g & 0xff) * 256 + (h & 0xff);
        ip_count = end_ip - start_ip + 1;
    #elif  0
        sscanf(content, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &e);
        start_ip = (a & 0xff) * 16777216 + (b & 0xff) *65536 + (c & 0xff) * 256 + (d & 0xff);
        ip_count = 1 << (32 - e);
    #elif 0
        sscanf(content + 14, "%d.%d.%d.%d|%d", &a, &b, &c, &d, &e);
        start_ip = (a & 0xff) * 16777216 + (b & 0xff) *65536 + (c & 0xff) * 256 + (d & 0xff);
        ip_count = e;  
    #else
        sscanf(content, "%d.%d.%d.%d %d", &a, &b, &c, &d, &e);   
                start_ip = (a & 0xff) * 16777216 + (b & 0xff) *65536 + (c & 0xff) * 256 + (d & 0xff);
        ip_count = 1 << (32 - e); 
    #endif
        
        mask = count_to_mask(ip_count);
        if(mask > 24)
        {
            mask = 24;
            start_ip &= 0xffffff00;
            ip_count = 256;
        }
        //printf("%u %u %u\n", start_ip, end_ip, ip_count);
        //printf("%d.%d.%d.%d/%d\n", a, b, c, d, mask);
        order_insert_list(&head, start_ip, 0, ip_count);
    }
    fclose(fp);

    //add_split_route(&new_tab, 0xac101f00, 0x10000);
    gen_agg_table(head, &new_tab);
    printf("# generate agg table\n");
    print_list(new_tab); 
    //printf("# generating reverse table\n");
    gen_reverse_table(new_tab, &reverse_tab);
    //print_list(reverse_tab); 
    //printf("# generate agg reverse table\n");
    gen_agg_table(reverse_tab, &agg_tab);
    //print_list(agg_tab); 

}