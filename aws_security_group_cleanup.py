import boto3


def region_report(region):
    # Security groups used by EC2
    ec2 = boto3.resource('ec2', region_name=region)
    client = boto3.client('ec2', region_name=region)
    sgs = list(ec2.security_groups.all())
    insts = list(ec2.instances.all())

    # All Security groups
    all_sgids = set([sg.group_id for sg in sgs])

    # Security groups used by EC2 instances
    all_inst_sgids = set([sg['GroupId'] for inst in insts for sg in inst.security_groups])

    # Security groups used by EC2 reservations
    instances_dict = client.describe_instances()
    reservations = instances_dict['Reservations']
    if not reservations:
        all_res_sgids = set([])
    if reservations:
        all_res_inst_sgids = set([k['GroupId'] for i in reservations \
                                  for j in i['Instances'] \
                                  for k in j['SecurityGroups']])

        all_res_inter_sgids = set([n['GroupId'] for i in reservations \
                                   for j in i['Instances'] \
                                   for m in j['NetworkInterfaces'] \
                                   for n in m['Groups']])
        all_res_sgids = all_res_inst_sgids | all_res_inter_sgids
    else:
        all_res_sgids = set([])

    # Security groups used by classic ELBs
    elb_client = boto3.client('elb', region_name=region)
    elbs = elb_client.describe_load_balancers()
    all_elbs_sgids = set([j for i in elbs['LoadBalancerDescriptions'] \
                          for j in i['SecurityGroups']])

    # Security groups used by ALBs
    elb2_client = boto3.client('elbv2', region_name=region)
    elb2s = elb2_client.describe_load_balancers()
    all_elb2s_sgids = set([j for i in elb2s['LoadBalancers'] \
                          for j in i['SecurityGroups']])

    # Security groups used by RDS
    rds_client = boto3.client('rds', region_name=region)
    rds = rds_client.describe_db_security_groups()
    all_rds_sgids = set([j for i in rds['DBSecurityGroups'] \
                          for j in i['EC2SecurityGroups']])

    # Skipping security groups used by OpsWork
    #ops_client = boto3.client('opsworks', region_name=region)
    #ops = ops_client.describe_instances(stackid)
    #all_ops_sgids = set([j for i in ops['Instances'] \
    #                           for j in i['SecurityGroupIds']])
    #print(all_ops_sgids)

    #
    #all_vpcs = set([sg.vpc_id for sg in sgs])

    # Making https://www.programiz.com/python-programming/set
    all_used_sgids = all_inst_sgids | all_res_sgids
    all_used_sgids = all_used_sgids | all_elbs_sgids
    all_used_sgids = all_used_sgids | all_elb2s_sgids
    all_used_sgids = all_used_sgids | all_rds_sgids
    unused_sgids = all_sgids - all_used_sgids

    # Deleting unused groups
    for id in unused_sgids:
        security_group = ec2.SecurityGroup(id)
        try:
            print("Deleting {} in regiona {}".format(id, region))
            security_group.delete()
        except Exception as e:
            print(e)
            print("{0} requires manual remediation.".format(security_group.group_name))

    print("-----------------------------")
    print("Activity Report", region)
    print("-----------------------------")

    print('Total SGs:', len(all_sgids))
    print('Total SGs in Instances:', len(all_inst_sgids))
    print('Total SGs in Reservations:', len(all_res_sgids))
    print('Total SGs in classic ELBs:', len(all_elbs_sgids))
    print('Total SGs in ALBs:', len(all_elb2s_sgids))
    print('Total SGs in RDSs:', len(all_rds_sgids))
    print('Total used SGs:', len(all_used_sgids))
    print('Orphaned SGs:', len(unused_sgids))
    print('Unattached SGs:', unused_sgids)

def main():
    # get a full list of the available regions
    client = boto3.client('ec2')
    regions_dict = client.describe_regions()
    region_list = [region['RegionName'] for region in regions_dict['Regions']]

    # Running report on each region
    [region_report(region) for region in region_list]

if __name__ == "__main__":
    main()
