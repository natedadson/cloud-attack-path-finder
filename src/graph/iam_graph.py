#!/usr/bin/env python3
"""
IAM Privilege Graph Builder
Creates a directed graph of AWS identities and their permissions

Author: Nathaniel Dadson
Independent Security Research
"""

import boto3
import pickle
import networkx as nx
from typing import Dict, List, Set, Tuple, Any
from collections import defaultdict


class IAMGraphBuilder:
    """
    Builds a directed graph of IAM relationships for privilege escalation analysis
    """
    
    def __init__(self, profile_name: str = "service-account-governor"):
        self.session = boto3.Session(profile_name=profile_name)
        self.iam_client = self.session.client('iam')
        self.graph = nx.DiGraph()
        
        self.nodes_found = {
            'users': 0,
            'roles': 0,
            'groups': 0,
            'resources': 0
        }
        
    def add_node_with_type(self, node_id: str, node_type: str, metadata: Dict = None):
        """Add a node to the graph with type information"""
        if metadata is None:
            metadata = {}
        metadata['type'] = node_type
        self.graph.add_node(node_id, **metadata)
        
    def discover_iam_users(self) -> List[Dict]:
        """Discover all IAM users in the account"""
        print("🔍 Discovering IAM users...")
        users = []
        
        try:
            paginator = self.iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    users.append(user)
                    self.add_node_with_type(
                        node_id=user['UserName'],
                        node_type='user',
                        metadata={
                            'arn': user['Arn'],
                            'created': user['CreateDate'].isoformat()
                        }
                    )
        except Exception as e:
            print(f"  ⚠️ Error listing users: {e}")
            
        self.nodes_found['users'] = len(users)
        print(f"  ✓ Found {len(users)} IAM users")
        return users
    
    def discover_iam_roles(self) -> List[Dict]:
        """Discover all IAM roles"""
        print("🔍 Discovering IAM roles...")
        roles = []
        
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    roles.append(role)
                    self.add_node_with_type(
                        node_id=role['RoleName'],
                        node_type='role',
                        metadata={
                            'arn': role['Arn'],
                            'created': role['CreateDate'].isoformat()
                        }
                    )
        except Exception as e:
            print(f"  ⚠️ Error listing roles: {e}")
            
        self.nodes_found['roles'] = len(roles)
        print(f"  ✓ Found {len(roles)} IAM roles")
        return roles
    
    def extract_assume_role_edges(self, role: Dict):
        """Find which identities can assume this role"""
        trust_policy = role.get('AssumeRolePolicyDocument', {})
        statements = trust_policy.get('Statement', [])
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
                
            principal = statement.get('Principal', {})
            
            if 'AWS' in principal:
                aws_principals = principal['AWS']
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                    
                for aws_principal in aws_principals:
                    if ':user/' in aws_principal:
                        username = aws_principal.split(':user/')[1]
                        self.graph.add_edge(username, role['RoleName'], 
                                           relation='can_assume',
                                           risk='HIGH')
                        print(f"    {username} → can_assume → {role['RoleName']}")
                        
                    elif ':role/' in aws_principal:
                        rolename = aws_principal.split(':role/')[1]
                        self.graph.add_edge(rolename, role['RoleName'],
                                           relation='can_assume',
                                           risk='HIGH')
                        print(f"    {rolename} → can_assume → {role['RoleName']}")
            
            if 'Service' in principal:
                service = principal['Service']
                if isinstance(service, str):
                    service = [service]
                self.graph.add_edge('AWS_Service', role['RoleName'],
                                   relation='service_can_assume',
                                   risk='MEDIUM',
                                   service_names=','.join(service))
    
    def build_complete_graph(self):
        """Build the complete privilege graph"""
        print("\n" + "="*60)
        print("Building IAM Privilege Graph")
        print("="*60)
        
        users = self.discover_iam_users()
        roles = self.discover_iam_roles()
        
        print("\n🔍 Discovering trust relationships...")
        for role in roles:
            self.extract_assume_role_edges(role)
        
        print("\n" + "="*60)
        print("Graph Statistics")
        print("="*60)
        print(f"  Total Nodes: {self.graph.number_of_nodes()}")
        print(f"  Total Edges: {self.graph.number_of_edges()}")
        print(f"  Node Types: {self.nodes_found}")
        
        return self.graph
    
    def export_graph(self, filename: str = "iam_graph.gpickle"):
        """Save graph using pickle (works with all NetworkX versions)"""
        with open(filename, 'wb') as f:
            pickle.dump(self.graph, f)
        print(f"\n💾 Graph saved to {filename}")
    
    def load_graph(self, filename: str = "iam_graph.gpickle"):
        """Load graph from pickle file"""
        with open(filename, 'rb') as f:
            self.graph = pickle.load(f)
        print(f"📂 Graph loaded from {filename}")
        return self.graph
    
    def find_shortest_path(self, source: str, target: str) -> List[str]:
        """Find shortest path between two nodes"""
        try:
            path = nx.shortest_path(self.graph, source=source, target=target)
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
    
    def find_all_admin_paths(self) -> List[List[str]]:
        """Find all paths to admin-equivalent privileges"""
        admin_paths = []
        
        # Find nodes that can assume admin roles
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get('type', 'unknown')
            
            # Check outgoing edges for HIGH risk
            for neighbor in self.graph.neighbors(node):
                edge_data = self.graph.get_edge_data(node, neighbor)
                if edge_data and edge_data.get('risk') == 'HIGH':
                    if node_type == 'user':
                        path = [node, neighbor]
                        admin_paths.append(path)
                        print(f"  ⚠️ Found: {node} → {neighbor}")
                        
        return admin_paths
    
    def print_attack_paths(self):
        """Print all discovered attack paths"""
        admin_paths = self.find_all_admin_paths()
        
        print("\n" + "="*60)
        print("🔴 PRIVILEGE ESCALATION PATHS")
        print("="*60)
        
        if admin_paths:
            print(f"\n⚠️ Found {len(admin_paths)} potential escalation paths:")
            for i, path in enumerate(admin_paths, 1):
                print(f"\n  Path {i}: {' → '.join(path)}")
        else:
            print("\n✅ No privilege escalation paths found")
        
        return admin_paths


if __name__ == "__main__":
    print("="*60)
    print("Cloud Attack Path Finder - Graph Builder")
    print("="*60)
    
    builder = IAMGraphBuilder()
    graph = builder.build_complete_graph()
    
    builder.print_attack_paths()
    builder.export_graph()
