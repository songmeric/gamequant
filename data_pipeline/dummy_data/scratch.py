def Base_3vs2(T1, T2, W, Dict):
    T1_C = list(itertools.combinations(T1,2))
    for t in T1_C:
        t = tuple(sorted(t))
        t = '/' + '/'.join(t) + '/'
        if t not in Dict:
            Dict[t] = {}
            T2_C = list(itertools.combinations(T2, 3))
            for i in T2_C:
                char = tuple(sorted(i))
                char = '/' + '/'.join(char) + '/'
                if char not in Dict[t]:
                    Dict[t][char] = [W]
                else:
                    print('error1')
    return Dict

def Base_3vs4(T1,T2,W,Dict):
    T1_C = list(itertools.combinations(T1,3))
    for t in T1_C:
        t = tuple(sorted(t))
        t = '/' + '/'.join(t) + '/'
        if t not in Dict:
            Dict[t] = {}
            T2_C = list(itertools.combinations(T2,4))
            for i in T2_C:
                char  = tuple(sorted(i))
                char = '/' + '/'.join(char) + '/'
                if char not in Dict[t]:
                    Dict[t][char] = [W]
                else:
                    print('error2')

def Base_5vs4(T1, T2, W, Dict):
    t = tuple(sorted(T1))
    t = '/' + '/'.join(t) + '/'
    if t not in Dict:
        Dict[t] = {}
        T2_C = list(itertools.combinations(T2,4))
        for i in T2_C:
            char = tuple(sorted(i))
            char = '/' + '/'.join(char) + '/'
            if char not in Dict[t]:
                Dict[t][char] = [W]
            else:
                print('error3')


Blue_first = input('Blue Team pick')
Red_first = input('Red Team pick')

